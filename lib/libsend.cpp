#include <pthread.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <map>
#include <deque>
#include <string>
#include <cassert>
#include <poll.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/timerfd.h>
#include <time.h>
#include "lib.h"
#include "utils.h"
#include "protocol.h"

using namespace std;

#define POLI_TYPE_SYN 1
#define POLI_TYPE_SYNACK 2
#define POLI_TYPE_ACK 3
#define POLI_TYPE_DATA 4

std::map<int, struct connection *> cons;
pthread_mutex_t g_cons_lock = PTHREAD_MUTEX_INITIALIZER;

struct pollfd data_fds[MAX_CONNECTIONS];
/* Used for timers per connection */
struct pollfd timer_fds[MAX_CONNECTIONS];
int fdmax = 0;

#define INIT_RTO_MS 100
#define MIN_RTO_MS 20
#define MAX_RTO_MS 1000
#define DUP_ACK_THRESHOLD 3

#define SEND_BUF_CAP (16 * 1024 * 1024)

static int g_cap_segs = 64;

struct Seg {
    uint32_t seq;
    std::string data;
    int64_t sent_ns;
    bool rexmit;

    Seg() : seq(0), sent_ns(0), rexmit(false) {}
};

struct SendState {
    std::deque<Seg> inflight;
    std::deque<Seg> pending;
    uint32_t next_seq;
    uint32_t base;
    int dup;
    int recv_window;
    size_t buffered;

    double srtt;
    double rttvar;
    int rto_ms;

    SendState() : next_seq(0), base(0), dup(0), recv_window(MAX_DATA_SIZE),
                  buffered(0), srtt(-1.0), rttvar(0.0), rto_ms(INIT_RTO_MS) {}
};

static std::map<int, SendState *> sstate;

static int64_t monotonic_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static void set_timer_fd(int tfd, int ms)
{
    struct itimerspec its;
    memset(&its, 0, sizeof(its));
    if (ms > 0) {
        its.it_value.tv_sec = ms / 1000;
        its.it_value.tv_nsec = (ms % 1000) * 1000000L;
    }
    int rc = timerfd_settime(tfd, 0, &its, NULL);
    assert(rc == 0);
}

static void arm_timer(struct connection *con, int ms)
{
    int idx = con->conn_id;
    assert(idx >= 0 && idx < MAX_CONNECTIONS);
    set_timer_fd(timer_fds[idx].fd, ms);
}

static void disarm_timer(struct connection *con)
{
    int idx = con->conn_id;
    assert(idx >= 0 && idx < MAX_CONNECTIONS);
    set_timer_fd(timer_fds[idx].fd, 0);
}

static void update_rto(SendState *ss, double sample_ms)
{
    if (ss->srtt < 0) {
        ss->srtt = sample_ms;
        ss->rttvar = sample_ms / 2.0;
    } else {
        ss->rttvar = 0.75 * ss->rttvar + 0.25 * fabs(ss->srtt - sample_ms);
        ss->srtt = 0.875 * ss->srtt + 0.125 * sample_ms;
    }

    int rto = (int)(ss->srtt + 4.0 * ss->rttvar);
    if (rto < MIN_RTO_MS)
        rto = MIN_RTO_MS;
    if (rto > MAX_RTO_MS)
        rto = MAX_RTO_MS;
    ss->rto_ms = rto;
}

static int window_segments(SendState *ss)
{
    int w = ss->recv_window / MAX_DATA_SIZE;
    if (w > g_cap_segs)
        w = g_cap_segs;
    return w;
}

static uint32_t poli_cksum(const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i < n; i++) {
        crc ^= b[i];
        for (int k = 0; k < 8; k++)
            crc = (crc >> 1) ^ (0xEDB88320u & (uint32_t)(-(int32_t)(crc & 1u)));
    }
    return ~crc;
}

static int poli_cksum_ok(const void *p, int n)
{
    if (n < (int)sizeof(uint32_t))
        return 0;
    uint32_t got;
    memcpy(&got, (const char *)p + n - sizeof(uint32_t), sizeof(uint32_t));
    return got == poli_cksum(p, n - sizeof(uint32_t));
}

static void send_segment(struct connection *con, const Seg &s)
{
    char buf[MAX_SEGMENT_SIZE];
    struct poli_tcp_data_hdr *h = (struct poli_tcp_data_hdr *)buf;
    h->protocol_id = POLI_PROTOCOL_ID;
    h->conn_id = (uint8_t)con->conn_id;
    h->type = POLI_TYPE_DATA;
    h->seq_num = htons((uint16_t)s.seq);
    h->len = htons((uint16_t)s.data.size());
    memcpy(buf + sizeof(*h), s.data.data(), s.data.size());

    size_t body = sizeof(*h) + s.data.size();
    uint32_t ck = poli_cksum(buf, body);
    memcpy(buf + body, &ck, sizeof(ck));

    int n = sendto(con->sockfd, buf, body + sizeof(ck), 0,
                   (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
    (void)n;
}

static void pump(struct connection *con, SendState *ss)
{
    int win = window_segments(ss);
    bool was_empty = ss->inflight.empty();

    while ((int)ss->inflight.size() < win && !ss->pending.empty()) {
        Seg s = ss->pending.front();
        ss->pending.pop_front();
        s.sent_ns = monotonic_ns();
        s.rexmit = false;
        ss->inflight.push_back(s);
        send_segment(con, s);
    }

    if (was_empty && !ss->inflight.empty())
        arm_timer(con, ss->rto_ms);
}

int send_data(int conn_id, char *buffer, int len)
{
    pthread_mutex_lock(&g_cons_lock);
    auto it = cons.find(conn_id);
    if (it == cons.end()) {
        pthread_mutex_unlock(&g_cons_lock);
        return -1;
    }
    struct connection *con = it->second;
    SendState *ss = sstate[conn_id];
    pthread_mutex_unlock(&g_cons_lock);

    pthread_mutex_lock(&con->con_lock);

    if (ss->buffered + (size_t)len > SEND_BUF_CAP) {
        pthread_mutex_unlock(&con->con_lock);
        return -1;
    }

    int off = 0;
    while (off < len) {
        int chunk = len - off;
        if (chunk > MAX_DATA_SIZE - (int)sizeof(uint32_t))
            chunk = MAX_DATA_SIZE - (int)sizeof(uint32_t);

        Seg s;
        s.seq = ss->next_seq++;
        s.data.assign(buffer + off, buffer + off + chunk);
        ss->pending.push_back(s);
        ss->buffered += chunk;
        off += chunk;
    }

    pump(con, ss);

    pthread_mutex_unlock(&con->con_lock);
    return len;
}

static void handle_ack(struct connection *con, SendState *ss,
                       struct poli_tcp_ctrl_hdr *h)
{
    uint32_t ack = ntohs(h->ack_num);
    ss->recv_window = ntohs(h->recv_window);

    if (ack > ss->base) {
        int64_t now = monotonic_ns();
        bool sampled = false;
        double sample_ms = 0.0;

        while (!ss->inflight.empty() && ss->inflight.front().seq < ack) {
            Seg &f = ss->inflight.front();
            if (!f.rexmit) {
                sample_ms = (now - f.sent_ns) / 1000000.0;
                sampled = true;
            }
            ss->buffered -= f.data.size();
            ss->inflight.pop_front();
        }

        if (sampled)
            update_rto(ss, sample_ms);

        ss->base = ack;
        ss->dup = 0;

        if (ss->inflight.empty())
            disarm_timer(con);
        else
            arm_timer(con, ss->rto_ms);
    } else if (ack == ss->base) {
        ss->dup++;
        if (ss->dup >= DUP_ACK_THRESHOLD && !ss->inflight.empty()) {
            ss->inflight.front().rexmit = true;
            send_segment(con, ss->inflight.front());
            ss->dup = 0;
            arm_timer(con, ss->rto_ms);
        }
    }

    pump(con, ss);
}

static void handle_timeout(struct connection *con, SendState *ss)
{
    if (!ss->inflight.empty()) {
        for (size_t i = 0; i < ss->inflight.size(); i++) {
            ss->inflight[i].rexmit = true;
            send_segment(con, ss->inflight[i]);
        }
        ss->dup = 0;
        ss->rto_ms *= 2;
        if (ss->rto_ms > MAX_RTO_MS)
            ss->rto_ms = MAX_RTO_MS;
        arm_timer(con, ss->rto_ms);
    } else if (!ss->pending.empty()) {
        Seg s = ss->pending.front();
        ss->pending.pop_front();
        s.sent_ns = monotonic_ns();
        s.rexmit = true;
        ss->inflight.push_back(s);
        send_segment(con, s);
        arm_timer(con, ss->rto_ms);
    } else {
        disarm_timer(con);
    }
}

void *sender_handler(void *arg)
{
    (void)arg;
    int res = 0;
    char buf[MAX_SEGMENT_SIZE];

    while (1) {
        pthread_mutex_lock(&g_cons_lock);
        bool empty = cons.empty();
        pthread_mutex_unlock(&g_cons_lock);
        if (empty) {
            usleep(1000);
            continue;
        }

        int conn_id = -1;
        do {
            res = recv_message_or_timeout(buf, MAX_SEGMENT_SIZE, &conn_id);
        } while (res == -14);

        pthread_mutex_lock(&g_cons_lock);
        auto it = cons.find(conn_id);
        if (it == cons.end()) {
            pthread_mutex_unlock(&g_cons_lock);
            continue;
        }
        struct connection *con = it->second;
        SendState *ss = sstate[conn_id];
        pthread_mutex_unlock(&g_cons_lock);

        pthread_mutex_lock(&con->con_lock);

        if (res == -1) {
            handle_timeout(con, ss);
        } else if (res >= (int)sizeof(struct poli_tcp_ctrl_hdr) + (int)sizeof(uint32_t) &&
                   poli_cksum_ok(buf, res)) {
            struct poli_tcp_ctrl_hdr *h = (struct poli_tcp_ctrl_hdr *)buf;
            if (h->protocol_id == POLI_PROTOCOL_ID && h->type == POLI_TYPE_ACK)
                handle_ack(con, ss, h);
        }

        pthread_mutex_unlock(&con->con_lock);
    }

    return NULL;
}

static void register_connection_fds(int conn_id, int sockfd)
{
    assert(conn_id >= 0 && conn_id < MAX_CONNECTIONS);

    data_fds[conn_id].fd = sockfd;
    data_fds[conn_id].events = POLLIN;
    data_fds[conn_id].revents = 0;

    int tfd = timerfd_create(CLOCK_MONOTONIC, 0);
    assert(tfd >= 0);
    timer_fds[conn_id].fd = tfd;
    timer_fds[conn_id].events = POLLIN;
    timer_fds[conn_id].revents = 0;
    set_timer_fd(tfd, 0);

    if (conn_id + 1 > fdmax)
        fdmax = conn_id + 1;
}

int setup_connection(uint32_t ip, uint16_t port)
{
    struct connection *con =
        (struct connection *)calloc(1, sizeof(struct connection));
    con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    assert(con->sockfd >= 0);

    memset(&con->servaddr, 0, sizeof(con->servaddr));
    con->servaddr.sin_family = AF_INET;
    con->servaddr.sin_addr.s_addr = ip;
    con->servaddr.sin_port = port;

    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 200000;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct poli_tcp_ctrl_hdr syn;
    memset(&syn, 0, sizeof(syn));
    syn.protocol_id = POLI_PROTOCOL_ID;
    syn.type = POLI_TYPE_SYN;
    char synbuf[sizeof(syn) + sizeof(uint32_t)];
    memcpy(synbuf, &syn, sizeof(syn));
    uint32_t synck = poli_cksum(synbuf, sizeof(syn));
    memcpy(synbuf + sizeof(syn), &synck, sizeof(synck));

    int assigned_conn = -1;
    int established = 0;

    for (int attempt = 0; attempt < 200 && !established; attempt++) {
        sendto(con->sockfd, synbuf, sizeof(synbuf), 0,
               (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

        char rbuf[MAX_SEGMENT_SIZE];
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        int n = recvfrom(con->sockfd, rbuf, sizeof(rbuf), 0,
                         (struct sockaddr *)&src, &slen);
        if (n < (int)sizeof(struct poli_tcp_ctrl_hdr) + (int)sizeof(uint32_t))
            continue;
        if (!poli_cksum_ok(rbuf, n))
            continue;
        n -= (int)sizeof(uint32_t);

        struct poli_tcp_ctrl_hdr *h = (struct poli_tcp_ctrl_hdr *)rbuf;
        if (h->protocol_id != POLI_PROTOCOL_ID || h->type != POLI_TYPE_SYNACK)
            continue;

        if (n < (int)sizeof(*h) + (int)sizeof(uint16_t))
            continue;

        uint16_t data_port_h;
        memcpy(&data_port_h, rbuf + sizeof(*h), sizeof(uint16_t));

        assigned_conn = h->conn_id;
        con->conn_id = assigned_conn;
        con->servaddr.sin_port = htons(data_port_h);

        SendState *ss = new SendState();
        ss->recv_window = ntohs(h->recv_window);
        if (ss->recv_window <= 0)
            ss->recv_window = MAX_DATA_SIZE;

        struct poli_tcp_ctrl_hdr ack;
        memset(&ack, 0, sizeof(ack));
        ack.protocol_id = POLI_PROTOCOL_ID;
        ack.conn_id = (uint8_t)assigned_conn;
        ack.type = POLI_TYPE_ACK;
        char ackbuf[sizeof(ack) + sizeof(uint32_t)];
        memcpy(ackbuf, &ack, sizeof(ack));
        uint32_t ackck = poli_cksum(ackbuf, sizeof(ack));
        memcpy(ackbuf + sizeof(ack), &ackck, sizeof(ackck));
        sendto(con->sockfd, ackbuf, sizeof(ackbuf), 0,
               (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));

        pthread_mutex_init(&con->con_lock, NULL);
        con->max_window_seq = g_cap_segs;

        pthread_mutex_lock(&g_cons_lock);
        sstate[assigned_conn] = ss;
        cons.insert({assigned_conn, con});
        register_connection_fds(assigned_conn, con->sockfd);
        pthread_mutex_unlock(&g_cons_lock);

        established = 1;
    }

    tv.tv_sec = 0;
    tv.tv_usec = 0;
    setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    assert(established);
    DEBUG_PRINT("Connection established (sender) conn_id=%d!\n", assigned_conn);
    return assigned_conn;
}

void init_sender(int speed, int delay)
{
    if (speed <= 0)
        speed = 8;
    if (delay <= 0)
        delay = 2;

    double bytes_per_sec = (double)speed * 1e6 / 8.0;
    double rtt_sec = (2.0 * (double)delay) / 1000.0;
    int bdp_segs = (int)((bytes_per_sec * rtt_sec) / MAX_DATA_SIZE);
    g_cap_segs = bdp_segs * 8;
    if (g_cap_segs < 64)
        g_cap_segs = 64;
    if (g_cap_segs > 1024)
        g_cap_segs = 1024;

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        data_fds[i].fd = -1;
        timer_fds[i].fd = -1;
    }

    pthread_t thread1;
    int ret = pthread_create(&thread1, NULL, sender_handler, NULL);
    assert(ret == 0);
}

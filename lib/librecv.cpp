#include <pthread.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <cstdint>
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

/* Wire-level message types used by this implementation. */
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

#define RECV_RTO_MS 200

static int g_listen_fd = -1;
static int g_next_conn_id = 0;

static int g_recv_cap = 9 * 1024;

struct RecvState {
    uint32_t expected;
    std::deque<char> delivered;
    std::map<uint32_t, std::string> oo;
    size_t oo_bytes;
    int last_adv;
    pthread_cond_t recv_cond;

    RecvState() : expected(0), oo_bytes(0), last_adv(0)
    {
        pthread_cond_init(&recv_cond, NULL);
    }
};

static std::map<int, RecvState *> rstate;

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

static int advertised_window(RecvState *rs)
{
    long used = (long)rs->delivered.size() + (long)rs->oo_bytes;
    long free_space = (long)g_recv_cap - used;
    if (free_space < 0)
        free_space = 0;
    if (free_space > 65535)
        free_space = 65535;
    return (int)free_space;
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

static void send_ctrl_ack(struct connection *con, uint32_t ack_num, int window)
{
    struct poli_tcp_ctrl_hdr h;
    memset(&h, 0, sizeof(h));
    h.protocol_id = POLI_PROTOCOL_ID;
    h.conn_id = (uint8_t)con->conn_id;
    h.type = POLI_TYPE_ACK;
    h.ack_num = htons((uint16_t)ack_num);
    h.recv_window = htons((uint16_t)window);

    char buf[sizeof(h) + sizeof(uint32_t)];
    memcpy(buf, &h, sizeof(h));
    uint32_t ck = poli_cksum(buf, sizeof(h));
    memcpy(buf + sizeof(h), &ck, sizeof(ck));

    int n = sendto(con->sockfd, buf, sizeof(buf), 0,
                   (struct sockaddr *)&con->servaddr, sizeof(con->servaddr));
    (void)n;
}

static void handle_data(struct connection *con, RecvState *rs, char *buf, int n)
{
    struct poli_tcp_data_hdr *h = (struct poli_tcp_data_hdr *)buf;
    uint32_t seq = ntohs(h->seq_num);
    int payload_len = ntohs(h->len);
    int avail = n - (int)sizeof(*h);

    if (payload_len > avail)
        payload_len = avail;
    if (payload_len < 0)
        payload_len = 0;

    char *payload = buf + sizeof(*h);

    if (seq == rs->expected) {
        rs->delivered.insert(rs->delivered.end(), payload, payload + payload_len);
        rs->expected++;

        auto it = rs->oo.find(rs->expected);
        while (it != rs->oo.end()) {
            rs->delivered.insert(rs->delivered.end(), it->second.begin(),
                                 it->second.end());
            rs->oo_bytes -= it->second.size();
            rs->oo.erase(it);
            rs->expected++;
            it = rs->oo.find(rs->expected);
        }

        pthread_cond_signal(&rs->recv_cond);
    } else if (seq > rs->expected) {
        if (rs->oo.find(seq) == rs->oo.end()) {
            long used = (long)rs->delivered.size() + (long)rs->oo_bytes;
            if (used + payload_len <= g_recv_cap) {
                rs->oo[seq] = std::string(payload, payload + payload_len);
                rs->oo_bytes += payload_len;
            }
        }
    }

    int win = advertised_window(rs);
    rs->last_adv = win;
    send_ctrl_ack(con, rs->expected, win);
    arm_timer(con, RECV_RTO_MS);
}

static void handle_timeout(struct connection *con, RecvState *rs)
{
    int win = advertised_window(rs);
    rs->last_adv = win;
    send_ctrl_ack(con, rs->expected, win);
    arm_timer(con, RECV_RTO_MS);
}

void *receiver_handler(void *arg)
{
    (void)arg;
    char segment[MAX_SEGMENT_SIZE];
    int res;

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
            res = recv_message_or_timeout(segment, MAX_SEGMENT_SIZE, &conn_id);
        } while (res == -14);

        pthread_mutex_lock(&g_cons_lock);
        auto it = cons.find(conn_id);
        if (it == cons.end()) {
            pthread_mutex_unlock(&g_cons_lock);
            continue;
        }
        struct connection *con = it->second;
        RecvState *rs = rstate[conn_id];
        pthread_mutex_unlock(&g_cons_lock);

        pthread_mutex_lock(&con->con_lock);

        if (res == -1) {
            handle_timeout(con, rs);
        } else if (res >= (int)sizeof(struct poli_tcp_data_hdr) + (int)sizeof(uint32_t) &&
                   poli_cksum_ok(segment, res)) {
            struct poli_tcp_data_hdr *h = (struct poli_tcp_data_hdr *)segment;
            if (h->protocol_id == POLI_PROTOCOL_ID && h->type == POLI_TYPE_DATA)
                handle_data(con, rs, segment, res - (int)sizeof(uint32_t));
        }

        pthread_mutex_unlock(&con->con_lock);
    }

    return NULL;
}

int recv_data(int conn_id, char *buffer, int len)
{
    pthread_mutex_lock(&g_cons_lock);
    auto it = cons.find(conn_id);
    if (it == cons.end()) {
        pthread_mutex_unlock(&g_cons_lock);
        return -1;
    }
    struct connection *con = it->second;
    RecvState *rs = rstate[conn_id];
    pthread_mutex_unlock(&g_cons_lock);

    pthread_mutex_lock(&con->con_lock);

    while (rs->delivered.empty())
        pthread_cond_wait(&rs->recv_cond, &con->con_lock);

    int cnt = (int)rs->delivered.size();
    if (cnt > len)
        cnt = len;

    for (int i = 0; i < cnt; i++) {
        buffer[i] = rs->delivered.front();
        rs->delivered.pop_front();
    }

    int win = advertised_window(rs);
    if (rs->last_adv < MAX_DATA_SIZE && win >= MAX_DATA_SIZE) {
        rs->last_adv = win;
        send_ctrl_ack(con, rs->expected, win);
    }

    pthread_mutex_unlock(&con->con_lock);
    return cnt;
}

static uint16_t socket_bound_port_h(int sockfd)
{
    struct sockaddr_in bound;
    socklen_t blen = sizeof(bound);
    int rc = getsockname(sockfd, (struct sockaddr *)&bound, &blen);
    assert(rc == 0);
    return ntohs(bound.sin_port);
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

int wait4connect(uint32_t ip, uint16_t port)
{
    if (g_listen_fd < 0) {
        g_listen_fd = socket(AF_INET, SOCK_DGRAM, 0);
        assert(g_listen_fd >= 0);

        int opt = 1;
        setsockopt(g_listen_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        struct sockaddr_in laddr;
        memset(&laddr, 0, sizeof(laddr));
        laddr.sin_family = AF_INET;
        laddr.sin_addr.s_addr = ip;
        laddr.sin_port = port;
        int rc = bind(g_listen_fd, (struct sockaddr *)&laddr, sizeof(laddr));
        assert(rc == 0);
    }

    while (1) {
        char rbuf[MAX_SEGMENT_SIZE];
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);
        int n = recvfrom(g_listen_fd, rbuf, sizeof(rbuf), 0,
                         (struct sockaddr *)&cli, &clen);
        if (n < (int)sizeof(struct poli_tcp_ctrl_hdr) + (int)sizeof(uint32_t))
            continue;
        if (!poli_cksum_ok(rbuf, n))
            continue;

        struct poli_tcp_ctrl_hdr *h = (struct poli_tcp_ctrl_hdr *)rbuf;
        if (h->protocol_id != POLI_PROTOCOL_ID || h->type != POLI_TYPE_SYN)
            continue;

        int dup = 0;
        pthread_mutex_lock(&g_cons_lock);
        for (auto const &x : cons) {
            struct connection *c = x.second;
            if (c->servaddr.sin_addr.s_addr == cli.sin_addr.s_addr &&
                c->servaddr.sin_port == cli.sin_port) {
                char sbuf[sizeof(struct poli_tcp_ctrl_hdr) + sizeof(uint16_t) + sizeof(uint32_t)];
                struct poli_tcp_ctrl_hdr *sh = (struct poli_tcp_ctrl_hdr *)sbuf;
                memset(sh, 0, sizeof(*sh));
                sh->protocol_id = POLI_PROTOCOL_ID;
                sh->conn_id = (uint8_t)c->conn_id;
                sh->type = POLI_TYPE_SYNACK;
                sh->recv_window = htons((uint16_t)g_recv_cap);
                uint16_t dp = socket_bound_port_h(c->sockfd);
                memcpy(sbuf + sizeof(*sh), &dp, sizeof(uint16_t));
                size_t sbody = sizeof(*sh) + sizeof(uint16_t);
                uint32_t sck = poli_cksum(sbuf, sbody);
                memcpy(sbuf + sbody, &sck, sizeof(sck));
                sendto(g_listen_fd, sbuf, sizeof(sbuf), 0,
                       (struct sockaddr *)&cli, sizeof(cli));
                dup = 1;
                break;
            }
        }
        pthread_mutex_unlock(&g_cons_lock);
        if (dup)
            continue;

        struct connection *con =
            (struct connection *)calloc(1, sizeof(struct connection));
        con->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        assert(con->sockfd >= 0);

        struct sockaddr_in daddr;
        memset(&daddr, 0, sizeof(daddr));
        daddr.sin_family = AF_INET;
        daddr.sin_addr.s_addr = htonl(INADDR_ANY);
        daddr.sin_port = 0;
        int rc = bind(con->sockfd, (struct sockaddr *)&daddr, sizeof(daddr));
        assert(rc == 0);

        uint16_t data_port = socket_bound_port_h(con->sockfd);

        con->conn_id = g_next_conn_id++;
        con->servaddr = cli;
        pthread_mutex_init(&con->con_lock, NULL);
        con->max_window_seq = 0;

        RecvState *rs = new RecvState();
        rs->last_adv = g_recv_cap;

        char sbuf[sizeof(struct poli_tcp_ctrl_hdr) + sizeof(uint16_t) + sizeof(uint32_t)];
        struct poli_tcp_ctrl_hdr *sh = (struct poli_tcp_ctrl_hdr *)sbuf;
        memset(sh, 0, sizeof(*sh));
        sh->protocol_id = POLI_PROTOCOL_ID;
        sh->conn_id = (uint8_t)con->conn_id;
        sh->type = POLI_TYPE_SYNACK;
        sh->recv_window = htons((uint16_t)g_recv_cap);
        memcpy(sbuf + sizeof(*sh), &data_port, sizeof(uint16_t));
        size_t sbody = sizeof(*sh) + sizeof(uint16_t);
        uint32_t sck = poli_cksum(sbuf, sbody);
        memcpy(sbuf + sbody, &sck, sizeof(sck));

        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int done = 0;
        for (int attempt = 0; attempt < 200 && !done; attempt++) {
            sendto(g_listen_fd, sbuf, sizeof(sbuf), 0,
                   (struct sockaddr *)&cli, sizeof(cli));

            char pbuf[MAX_SEGMENT_SIZE];
            struct sockaddr_in psrc;
            socklen_t pslen = sizeof(psrc);
            int pn = recvfrom(con->sockfd, pbuf, sizeof(pbuf), MSG_PEEK,
                              (struct sockaddr *)&psrc, &pslen);
            if (pn >= (int)sizeof(struct poli_tcp_ctrl_hdr) + (int)sizeof(uint32_t) &&
                poli_cksum_ok(pbuf, pn)) {
                struct poli_tcp_ctrl_hdr *ph = (struct poli_tcp_ctrl_hdr *)pbuf;
                if (ph->protocol_id == POLI_PROTOCOL_ID &&
                    ph->type == POLI_TYPE_ACK) {
                    recvfrom(con->sockfd, pbuf, sizeof(pbuf), 0,
                             (struct sockaddr *)&psrc, &pslen);
                }
                done = 1;
            }
        }

        tv.tv_sec = 0;
        tv.tv_usec = 0;
        setsockopt(con->sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int cid = con->conn_id;
        pthread_mutex_lock(&g_cons_lock);
        rstate[cid] = rs;
        cons.insert({cid, con});
        register_connection_fds(cid, con->sockfd);
        pthread_mutex_unlock(&g_cons_lock);

        arm_timer(con, RECV_RTO_MS);

        DEBUG_PRINT("Connection established (receiver) conn_id=%d!\n", cid);
        return cid;
    }
}

void init_receiver(int recv_buffer_bytes)
{
    if (recv_buffer_bytes > 0)
        g_recv_cap = recv_buffer_bytes;

    for (int i = 0; i < MAX_CONNECTIONS; i++) {
        data_fds[i].fd = -1;
        timer_fds[i].fd = -1;
    }

    pthread_t thread1;
    int ret = pthread_create(&thread1, NULL, receiver_handler, NULL);
    assert(ret == 0);
}

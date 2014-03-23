#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <locale.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#ifndef __MINGW32__
#include <errno.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#endif

#ifdef __APPLE__
#include <launch.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <sys/resource.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_SYS_IOCTL_H) && defined(HAVE_NET_IF_H) && defined(__linux__)
#include <net/if.h>
#include <sys/ioctl.h>
#define SET_INTERFACE
#endif

#ifdef __MINGW32__
#include "win32.h"
#endif

#include "utils.h"
#include "local.h"
#include "socks5.h"

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

#ifndef BUF_SIZE
#define BUF_SIZE 512
#endif

int verbose = 0;
int udprelay = 0;

int launchd = 0;
launchd_ctx_t launchd_ctx;

#ifndef __MINGW32__
static int setnonblocking(int fd)
{
    int flags;
    if (-1 ==(flags = fcntl(fd, F_GETFL, 0)))
        flags = 0;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}
#endif

#ifdef SET_INTERFACE
int setinterface(int socket_fd, const char* interface_name)
{
    struct ifreq interface;
    memset(&interface, 0, sizeof(interface));
    strncpy(interface.ifr_name, interface_name, IFNAMSIZ);
    int res = setsockopt(socket_fd, SOL_SOCKET, SO_BINDTODEVICE, &interface, sizeof(struct ifreq));
    return res;
}
#endif

int create_and_bind(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int s, listen_sock;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC; /* Return IPv4 and IPv6 choices */
    hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */

    s = getaddrinfo(addr, port, &hints, &result);
    if (s != 0)
    {
        LOGD("getaddrinfo: %s", gai_strerror(s));
        return -1;
    }

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        listen_sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (listen_sock == -1)
            continue;

        int opt = 1;
        setsockopt(listen_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(listen_sock, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
        setsockopt(listen_sock, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

        s = bind(listen_sock, rp->ai_addr, rp->ai_addrlen);
        if (s == 0)
        {
            /* We managed to bind successfully! */
            break;
        }
        else
        {
            ERROR("bind");
        }

        close(listen_sock);
    }

    if (rp == NULL)
    {
        LOGE("Could not bind");
        return -1;
    }

    freeaddrinfo(result);

    return listen_sock;
}

static void server_recv_cb (EV_P_ ev_io *w, int revents)
{
    struct server_ctx *server_recv_ctx = (struct server_ctx *)w;
    struct server *server = server_recv_ctx->server;
    struct remote *remote = server->remote;

    if (remote == NULL)
    {
        close_and_free_server(EV_A_ server);
        return;
    }

    ssize_t r = recv(server->fd, remote->buf, BUF_SIZE, 0);

    if (r == 0)
    {
        // connection closed
        remote->buf_len = 0;
        remote->buf_idx = 0;
        close_and_free_server(EV_A_ server);
        if (remote != NULL)
        {
            ev_io_start(EV_A_ &remote->send_ctx->io);
        }
        return;
    }
    else if(r < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // no data
            // continue to wait for recv
            return;
        }
        else
        {
            ERROR("server recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    // local socks5 server
    if (server->stage == 5)
    {
        remote->buf = ss_encrypt(BUF_SIZE, remote->buf, &r, server->e_ctx);
        if (remote->buf == NULL)
        {
            LOGE("invalid password or cipher");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
        int s = send(remote->fd, remote->buf, r, 0);
        if(s == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // no data, wait for send
                remote->buf_len = r;
                remote->buf_idx = 0;
                ev_io_stop(EV_A_ &server_recv_ctx->io);
                ev_io_start(EV_A_ &remote->send_ctx->io);
                return;
            }
            else
            {
                ERROR("send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
        else if(s < r)
        {
            remote->buf_len = r - s;
            remote->buf_idx = s;
            ev_io_stop(EV_A_ &server_recv_ctx->io);
            ev_io_start(EV_A_ &remote->send_ctx->io);
            return;
        }
    }
    else if (server->stage == 0)
    {
        struct method_select_response response;
        response.ver = SVERSION;
        response.method = 0;
        char *send_buf = (char *)&response;
        send(server->fd, send_buf, sizeof(response), 0);
        server->stage = 1;
        return;
    }
    else if (server->stage == 1)
    {
        struct socks5_request *request = (struct socks5_request *)remote->buf;

        struct sockaddr_in sock_addr;
        memset(&sock_addr, 0, sizeof(sock_addr));

        if (udprelay && request->cmd == 3)
        {
            socklen_t addr_len = sizeof(sock_addr);
            getsockname(server->fd, (struct sockaddr *)&sock_addr,
                        &addr_len);
            if (verbose)
            {
                LOGD("udp assc request accepted.");
            }
        }
        else if (request->cmd != 1)
        {
            LOGE("unsupported cmd: %d", request->cmd);
            struct socks5_response response;
            response.ver = SVERSION;
            response.rep = CMD_NOT_SUPPORTED;
            response.rsv = 0;
            response.atyp = 1;
            char *send_buf = (char *)&response;
            send(server->fd, send_buf, 4, 0);
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
        else
        {
            char *ss_addr_to_send = malloc(BUF_SIZE);
            ssize_t addr_len = 0;
            ss_addr_to_send[addr_len++] = request->atyp;

            // get remote addr and port
            if (request->atyp == 1)
            {
                // IP V4
                size_t in_addr_len = sizeof(struct in_addr);
                memcpy(ss_addr_to_send + addr_len, remote->buf + 4, in_addr_len + 2);
                addr_len += in_addr_len + 2;

                if (verbose)
                {
                    char host[INET_ADDRSTRLEN];
                    uint16_t port = ntohs(*(uint16_t *)(remote->buf + 4 + in_addr_len));
                    inet_ntop(AF_INET, (const void *)(remote->buf + 4),
                              host, INET_ADDRSTRLEN);
                    LOGD("connect to %s:%d", host, port);
                }

            }
            else if (request->atyp == 3)
            {
                // Domain name
                uint8_t name_len = *(uint8_t *)(remote->buf + 4);
                ss_addr_to_send[addr_len++] = name_len;
                memcpy(ss_addr_to_send + addr_len, remote->buf + 4 + 1, name_len + 2);
                addr_len += name_len + 2;

                if (verbose)
                {
                    char host[256];
                    uint16_t port = ntohs(*(uint16_t *)(remote->buf + 4 + 1 + name_len));
                    memcpy(host, remote->buf + 4 + 1, name_len);
                    host[name_len] = '\0';
                    LOGD("connect to %s:%d", host, port);
                }

            }
            else if (request->atyp == 4)
            {
                // IP V6
                size_t in6_addr_len = sizeof(struct in6_addr);
                memcpy(ss_addr_to_send + addr_len, remote->buf + 4, in6_addr_len + 2);
                addr_len += in6_addr_len + 2;

                if (verbose)
                {
                    char host[INET6_ADDRSTRLEN];
                    uint16_t port = ntohs(*(uint16_t *)(remote->buf + 4 + in6_addr_len));
                    inet_ntop(AF_INET6, (const void *)(remote->buf + 4),
                              host, INET6_ADDRSTRLEN);
                    LOGD("connect to %s:%d", host, port);
                }

            }
            else
            {
                LOGE("unsupported addrtype: %d", request->atyp);
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            ss_addr_to_send = ss_encrypt(BUF_SIZE, ss_addr_to_send, &addr_len, server->e_ctx);
            if (ss_addr_to_send == NULL)
            {
                LOGE("invalid password or cipher");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
            int s = send(remote->fd, ss_addr_to_send, addr_len, 0);
            free(ss_addr_to_send);

            if (s < addr_len)
            {
                LOGE("failed to send remote addr.");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }

            server->stage = 5;
            ev_io_start(EV_A_ &remote->recv_ctx->io);
        }

        // Fake reply
        struct socks5_response response;
        response.ver = SVERSION;
        response.rep = 0;
        response.rsv = 0;
        response.atyp = 1;

        memcpy(server->buf, &response, sizeof(struct socks5_response));
        memcpy(server->buf + sizeof(struct socks5_response), &sock_addr.sin_addr, sizeof(sock_addr.sin_addr));
        memcpy(server->buf + sizeof(struct socks5_response) + sizeof(sock_addr.sin_addr),
               &sock_addr.sin_port, sizeof(sock_addr.sin_port));

        int reply_size = sizeof(struct socks5_response) + sizeof(sock_addr.sin_addr) + sizeof(sock_addr.sin_port);
        int s = send(server->fd, server->buf, reply_size, 0);
        if (s < reply_size)
        {
            LOGE("failed to send fake reply.");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }

        if (request->cmd == 3) {
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }
}

static void server_send_cb (EV_P_ ev_io *w, int revents)
{
    struct server_ctx *server_send_ctx = (struct server_ctx *)w;
    struct server *server = server_send_ctx->server;
    struct remote *remote = server->remote;
    if (server->buf_len == 0)
    {
        // close and free
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }
    else
    {
        // has data to send
        ssize_t s = send(server->fd, server->buf + server->buf_idx,
                         server->buf_len, 0);
        if (s < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
            {
                ERROR("send");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
            }
            return;
        }
        else if (s < server->buf_len)
        {
            // partly sent, move memory, wait for the next time to send
            server->buf_len -= s;
            server->buf_idx += s;
            return;
        }
        else
        {
            // all sent out, wait for reading
            server->buf_len = 0;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ &server_send_ctx->io);
            if (remote != NULL)
            {
                ev_io_start(EV_A_ &remote->recv_ctx->io);
            }
            else
            {
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
        }
    }

}

static void remote_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    struct remote_ctx *remote_ctx = (struct remote_ctx *) (((void*)watcher)
                                    - sizeof(ev_io));
    struct remote *remote = remote_ctx->remote;
    struct server *server = remote->server;

    if (verbose) {
        LOGD("remote timeout");
    }

    ev_timer_stop(EV_A_ watcher);

    if (server == NULL)
    {
        close_and_free_remote(EV_A_ remote);
        return;
    }
    close_and_free_remote(EV_A_ remote);
    close_and_free_server(EV_A_ server);
}

static void remote_recv_cb (EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_recv_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_recv_ctx->remote;
    struct server *server = remote->server;
    if (server == NULL)
    {
        close_and_free_remote(EV_A_ remote);
        return;
    }

    ssize_t r = recv(remote->fd, server->buf, BUF_SIZE, 0);

    if (r == 0)
    {
        // connection closed
        server->buf_len = 0;
        server->buf_idx = 0;
        close_and_free_remote(EV_A_ remote);
        if (server != NULL)
        {
            ev_io_start(EV_A_ &server->send_ctx->io);
        }
        return;
    }
    else if(r < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // no data
            // continue to wait for recv
            return;
        }
        else
        {
            ERROR("remote recv");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }

    server->buf = ss_decrypt(BUF_SIZE, server->buf, &r, server->d_ctx);
    if (server->buf == NULL)
    {
        LOGE("invalid password or cipher");
        close_and_free_remote(EV_A_ remote);
        close_and_free_server(EV_A_ server);
        return;
    }
    int s = send(server->fd, server->buf, r, 0);

    if (s == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // no data, wait for send
            server->buf_len = r;
            server->buf_idx = 0;
            ev_io_stop(EV_A_ &remote_recv_ctx->io);
            ev_io_start(EV_A_ &server->send_ctx->io);
            return;
        }
        else
        {
            ERROR("send");
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }
    else if (s < r)
    {
        server->buf_len = r - s;
        server->buf_idx = s;
        ev_io_stop(EV_A_ &remote_recv_ctx->io);
        ev_io_start(EV_A_ &server->send_ctx->io);
        return;
    }
}

static void remote_send_cb (EV_P_ ev_io *w, int revents)
{
    struct remote_ctx *remote_send_ctx = (struct remote_ctx *)w;
    struct remote *remote = remote_send_ctx->remote;
    struct server *server = remote->server;

    if (!remote_send_ctx->connected)
    {

        struct sockaddr_storage addr;
        socklen_t len = sizeof addr;
        int r = getpeername(remote->fd, (struct sockaddr*)&addr, &len);
        if (r == 0)
        {
            remote_send_ctx->connected = 1;
            ev_io_stop(EV_A_ &remote_send_ctx->io);
            ev_timer_stop(EV_A_ &remote_send_ctx->watcher);
            ev_io_start(EV_A_ &server->recv_ctx->io);
            return;
        }
        else
        {
            ERROR("getpeername");
            // not connected
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
    }
    else
    {
        if (remote->buf_len == 0)
        {
            // close and free
            close_and_free_remote(EV_A_ remote);
            close_and_free_server(EV_A_ server);
            return;
        }
        else
        {
            // has data to send
            ssize_t s = send(remote->fd, remote->buf + remote->buf_idx,
                             remote->buf_len, 0);
            if (s < 0)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    ERROR("send");
                    // close and free
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                }
                return;
            }
            else if (s < remote->buf_len)
            {
                // partly sent, move memory, wait for the next time to send
                remote->buf_len -= s;
                remote->buf_idx += s;
                return;
            }
            else
            {
                // all sent out, wait for reading
                remote->buf_len = 0;
                remote->buf_idx = 0;
                ev_io_stop(EV_A_ &remote_send_ctx->io);
                if (server != NULL)
                {
                    ev_io_start(EV_A_ &server->recv_ctx->io);
                }
                else
                {
                    close_and_free_remote(EV_A_ remote);
                    close_and_free_server(EV_A_ server);
                    return;
                }
            }
        }

    }
}

struct remote* new_remote(int fd, int timeout)
{
    struct remote *remote;
    remote = malloc(sizeof(struct remote));
    remote->buf = malloc(BUF_SIZE);
    remote->recv_ctx = malloc(sizeof(struct remote_ctx));
    remote->send_ctx = malloc(sizeof(struct remote_ctx));
    remote->fd = fd;
    ev_io_init(&remote->recv_ctx->io, remote_recv_cb, fd, EV_READ);
    ev_io_init(&remote->send_ctx->io, remote_send_cb, fd, EV_WRITE);
    ev_timer_init(&remote->send_ctx->watcher, remote_timeout_cb, timeout, 0);
    remote->recv_ctx->remote = remote;
    remote->recv_ctx->connected = 0;
    remote->send_ctx->remote = remote;
    remote->send_ctx->connected = 0;
    remote->buf_len = 0;
    remote->buf_idx = 0;
    return remote;
}

static void free_remote(struct remote *remote)
{
    if (remote != NULL)
    {
        if (remote->server != NULL)
        {
            remote->server->remote = NULL;
        }
        if (remote->buf)
        {
            free(remote->buf);
        }
        free(remote->recv_ctx);
        free(remote->send_ctx);
        free(remote);
    }
}

static void close_and_free_remote(EV_P_ struct remote *remote)
{
    if (remote != NULL)
    {
        ev_timer_stop(EV_A_ &remote->send_ctx->watcher);
        ev_io_stop(EV_A_ &remote->send_ctx->io);
        ev_io_stop(EV_A_ &remote->recv_ctx->io);
        close(remote->fd);
        free_remote(remote);
    }
}

struct server* new_server(int fd, int method)
{
    struct server *server;
    server = malloc(sizeof(struct server));
    server->buf = malloc(BUF_SIZE);
    server->recv_ctx = malloc(sizeof(struct server_ctx));
    server->send_ctx = malloc(sizeof(struct server_ctx));
    server->fd = fd;
    ev_io_init(&server->recv_ctx->io, server_recv_cb, fd, EV_READ);
    ev_io_init(&server->send_ctx->io, server_send_cb, fd, EV_WRITE);
    server->recv_ctx->server = server;
    server->recv_ctx->connected = 0;
    server->send_ctx->server = server;
    server->send_ctx->connected = 0;
    server->stage = 0;
    if (method)
    {
        server->e_ctx = malloc(sizeof(struct enc_ctx));
        server->d_ctx = malloc(sizeof(struct enc_ctx));
        enc_ctx_init(method, server->e_ctx, 1);
        enc_ctx_init(method, server->d_ctx, 0);
    }
    else
    {
        server->e_ctx = NULL;
        server->d_ctx = NULL;
    }
    server->buf_len = 0;
    server->buf_idx = 0;
    return server;
}

static void free_server(struct server *server)
{
    if (server != NULL)
    {
        if (server->remote != NULL)
        {
            server->remote->server = NULL;
        }
        if (server->e_ctx != NULL)
        {
            cipher_context_release(&server->e_ctx->evp);
            free(server->e_ctx);
        }
        if (server->d_ctx != NULL)
        {
            cipher_context_release(&server->d_ctx->evp);
            free(server->d_ctx);
        }
        if (server->buf)
        {
            free(server->buf);
        }
        free(server->recv_ctx);
        free(server->send_ctx);
        free(server);
    }
}

static void close_and_free_server(EV_P_ struct server *server)
{
    if (server != NULL)
    {
        ev_io_stop(EV_A_ &server->send_ctx->io);
        ev_io_stop(EV_A_ &server->recv_ctx->io);
        close(server->fd);
        free_server(server);
    }
}

static void accept_cb (EV_P_ ev_io *w, int revents)
{
    struct listen_ctx *listener = (struct listen_ctx *)w;
    int serverfd = accept(listener->fd, NULL, NULL);
    if (serverfd == -1)
    {
        ERROR("accept");
        return;
    }
    setnonblocking(serverfd);
    int opt = 1;
    setsockopt(serverfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(serverfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    struct addrinfo hints, *res;
    int sockfd;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
#ifdef __APPLE__
    if (verbose)
    {
        LOGD("connect to %s:%s", launchd_ctx.remote_addr, launchd_ctx.remote_port);
    }
    int err = getaddrinfo(launchd_ctx.remote_addr, launchd_ctx.remote_port, &hints, &res);
    if (err)
    {
        ERROR("getaddrinfo");
        return;
    }
#else
    int index = rand() % listener->remote_num;
    if (verbose)
    {
        LOGD("connect to %s:%s", listener->remote_addr[index].host, listener->remote_addr[index].port);
    }
    int err = getaddrinfo(listener->remote_addr[index].host, listener->remote_addr[index].port, &hints, &res);
    if (err)
    {
        ERROR("getaddrinfo");
        return;
    }
#endif

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0)
    {
        ERROR("socket");
        freeaddrinfo(res);
        return;
    }

    setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
#ifdef SO_NOSIGPIPE
    setsockopt(sockfd, SOL_SOCKET, SO_NOSIGPIPE, &opt, sizeof(opt));
#endif

    // Setup
    setnonblocking(sockfd);
#ifdef SET_INTERFACE
    if (listener->iface) setinterface(sockfd, listener->iface);
#endif

    struct server *server = new_server(serverfd, listener->method);
    struct remote *remote = new_remote(sockfd, listener->timeout);
    server->remote = remote;
    remote->server = server;
    connect(sockfd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    // listen to remote connected event
    ev_io_start(EV_A_ &remote->send_ctx->io);
    ev_timer_start(EV_A_ &remote->send_ctx->watcher);
}

static void conf_listen_ctx(struct listen_ctx *p_listen_ctx, int remote_num, \
    char *remote_port, ss_addr_t *remote_addr, char *timeout, char *iface, int m)
{
#ifndef __APPLE__
    int index = 0;

    p_listen_ctx->remote_num = remote_num;
    p_listen_ctx->remote_addr = remote_addr;
    while (remote_num > 0) {
        index = --remote_num;
        if (remote_addr[index].port == NULL) {
            remote_addr[index].port = remote_port;
        }
    }
#endif
    p_listen_ctx->timeout = atoi(timeout);
#ifndef __APPLE__
    p_listen_ctx->iface = iface;
#endif
    p_listen_ctx->method = m;
}

#ifdef __APPLE__
static void launchd_reload_conf(void)
{
    int i;
    if (launchd_ctx.conf_path != NULL) {
        jconf_t *conf = read_jconf(launchd_ctx.conf_path);
        if (strcmp(launchd_ctx.password, conf->password) != 0 || \
            strcmp(launchd_ctx.method, conf->method) != 0) {
            launchd_ctx.cipher_mode = enc_init(conf->password, conf->method);
            save_str(&launchd_ctx.password, strdup(conf->password));
            save_str(&launchd_ctx.method, strdup(conf->method));
            if (verbose) {
                LOGD("reloading ciphers... %s", conf->method);
            }
        }
        launchd_ctx.except_num = conf->except_num;
        launchd_ctx.except_list = conf->except_list;
        launchd_ctx.pac_port = conf->pac_port;
        launchd_ctx.pac_path = conf->pac_path;
        strlcpy(launchd_ctx.local_port, conf->local_port, sizeof(launchd_ctx.local_port));
        strlcpy(launchd_ctx.remote_addr, conf->remote_addr[0].host, sizeof(launchd_ctx.remote_addr));
        strlcpy(launchd_ctx.remote_port, conf->remote_port, sizeof(launchd_ctx.remote_port));
        for (i = 0; i < launchd_ctx.local_ctxs_len; i++) {
            conf_listen_ctx(&launchd_ctx.local_ctxs[i], conf->remote_num, conf->remote_port, \
                conf->remote_addr, conf->timeout, NULL, launchd_ctx.cipher_mode);
        }
        if (verbose) {
            LOGD("config reloaded.");
        }
    }
}

static int launchd_set_proxy(CFDictionaryRef proxyDict, CFDictionaryRef dnsDict)
{
    int ret = 1;
    CFIndex index;
    SCPreferencesRef pref = SCPreferencesCreate(0, CFSTR("shadow"), 0);
    if (pref == NULL) {
        LOGE("cannot read system preferences.");
        return 0;
    }
    CFDictionaryRef services = SCPreferencesGetValue(pref, CFSTR("NetworkServices"));
    if (services == NULL) {
        LOGE("cannot read system network services.");
        CFRelease(pref);
        return 0;
    }
    CFDictionaryRef serviceDict = CFDictionaryCreateCopy(kCFAllocatorDefault, services);
    CFIndex count = CFDictionaryGetCount(serviceDict);
    CFTypeRef *keysTypeRef = (CFTypeRef *) malloc(count * sizeof(CFTypeRef));
    CFDictionaryGetKeysAndValues(serviceDict, (const void **) keysTypeRef, NULL);
    const void **allKeys = (const void **) keysTypeRef;
    for (index = 0; index < count; index++) {
        CFStringRef key = allKeys[index];
        CFDictionaryRef dict = CFDictionaryGetValue(serviceDict, key);
        CFStringRef rank = NULL;
        if (dict) {
            rank = CFDictionaryGetValue(dict, CFSTR("PrimaryRank"));
        }
        if (rank == NULL || CFStringCompare(rank, CFSTR("Never"), 0) != kCFCompareEqualTo) {
            CFStringRef path = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("/NetworkServices/%@/Proxies"), key);
            ret &= SCPreferencesPathSetValue(pref, path, proxyDict);
            CFRelease(path);
            
            if (dnsDict != NULL) {
                CFStringRef path = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("/NetworkServices/%@/DNS"), key);
                ret &= SCPreferencesPathSetValue(pref, path, dnsDict);
                CFRelease(path);
            }
        }
    }
    free(allKeys);
    CFRelease(serviceDict);
    ret &= SCPreferencesCommitChanges(pref);
    ret &= SCPreferencesApplyChanges(pref);
    SCPreferencesSynchronize(pref);
    SCDynamicStoreRef store = SCDynamicStoreCreate(0, CFSTR("shadow"), 0, 0);
    CFRelease(store);
    CFRelease(pref);
    return ret;
}

static int launchd_get_proxy_dict(int enabled, int is_socks, int set_dns, int dns_enabled)
{
    int i;
    int ret;
    CFMutableDictionaryRef proxyDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    int zero = 0;
    CFNumberRef zeroNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &zero);
    if (enabled) {
        int one = 1;
        int two = 2;
        CFNumberRef oneNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &one);
        CFNumberRef twoNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &two);
        if (is_socks) {
            int local_loop = 0;
            int local_host = 0;
            CFMutableArrayRef exceptArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            if (launchd_ctx.except_num > 0) {
                for (i = 0; i < launchd_ctx.except_num; i++) {
                    char *except_addr = launchd_ctx.except_list[i];
                    if (except_addr != NULL) {
                        if (strcmp(except_addr, "127.0.0.1") == 0) {
                            local_loop = 1;
                        }
                        if (strcmp(except_addr, "localhost") == 0) {
                            local_host = 1;
                        }
                        CFStringRef exceptAddr = CFStringCreateWithCString(kCFAllocatorDefault, except_addr, kCFStringEncodingUTF8);
                        CFArrayAppendValue(exceptArray, exceptAddr);
                        CFRelease(exceptAddr);
                    }
                }
            }
            if (!local_loop) {
                CFArrayAppendValue(exceptArray, CFSTR("127.0.0.1"));
            }
            if (!local_host) {
                CFArrayAppendValue(exceptArray, CFSTR("localhost"));
            }
            CFDictionarySetValue(proxyDict, CFSTR("ExceptionsList"), exceptArray);
            CFRelease(exceptArray);
            int port = atoi(launchd_ctx.local_port);
            CFNumberRef portNumber = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &port);
            CFDictionarySetValue(proxyDict, CFSTR("SOCKSEnable"), oneNumber);
            CFDictionarySetValue(proxyDict, CFSTR("SOCKSProxy"), CFSTR("127.0.0.1"));
            CFDictionarySetValue(proxyDict, CFSTR("SOCKSPort"), portNumber);
            CFRelease(portNumber);
        } else {
            CFDictionarySetValue(proxyDict, CFSTR("HTTPEnable"), zeroNumber);
            CFDictionarySetValue(proxyDict, CFSTR("HTTPProxyType"), twoNumber);
            CFDictionarySetValue(proxyDict, CFSTR("HTTPSEnable"), zeroNumber);
            CFDictionarySetValue(proxyDict, CFSTR("ProxyAutoConfigEnable"), oneNumber);
            CFStringRef addrString = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("http://127.0.0.1:%s/proxy.pac"), launchd_ctx.pac_port);
            CFDictionarySetValue(proxyDict, CFSTR("ProxyAutoConfigURLString"), addrString);
            CFRelease(addrString);
        }
        CFRelease(oneNumber);
        CFRelease(twoNumber);
    } else {
        CFDictionarySetValue(proxyDict, CFSTR("HTTPEnable"), zeroNumber);
        CFDictionarySetValue(proxyDict, CFSTR("HTTPProxyType"), zeroNumber);
        CFDictionarySetValue(proxyDict, CFSTR("HTTPSEnable"), zeroNumber);
        CFDictionarySetValue(proxyDict, CFSTR("ProxyAutoConfigEnable"), zeroNumber);
    }
    CFRelease(zeroNumber);
    
    if (!set_dns) {
        ret = launchd_set_proxy(proxyDict, NULL);
    } else {
        CFMutableDictionaryRef dnsDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if (dns_enabled) {
            CFMutableArrayRef dnsArray = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
            CFArrayAppendValue(dnsArray, CFSTR("8.8.8.8"));
            CFDictionarySetValue(dnsDict, CFSTR("ServerAddresses"), dnsArray);
            CFRelease(dnsArray);
        }
        ret = launchd_set_proxy(proxyDict, dnsDict);
        CFRelease(dnsDict);
    }
    
    CFRelease(proxyDict);
    return ret;
}

static void tun2socks_reachability_callback(SCNetworkReachabilityRef target, SCNetworkReachabilityFlags flags, void* info)
{
    // Reset route tables when reachability changed
    if (launchd_ctx.tun2socks_enabled) {
        if (verbose) {
            LOGD("network changed, resetting routes...");
        }
        tun2socks_route_setup(0);
        tun2socks_route_setup(1);
    }
}

static int tun2socks_reachability_register(int enabled, const char *gateway)
{
    int retValue = 0;
    
    if (launchd_ctx.tun2socks_reachability != NULL) {
        if (!SCNetworkReachabilitySetDispatchQueue(launchd_ctx.tun2socks_reachability, NULL)) {
            retValue = -1;
        }
        CFRelease(launchd_ctx.tun2socks_reachability);
        launchd_ctx.tun2socks_reachability = NULL;
    }
    
    if (!enabled) {
        return retValue;
    }
    
    // Monitor reachability to current gateway
    SCNetworkReachabilityContext context = {0, NULL, NULL, NULL, NULL};
    launchd_ctx.tun2socks_reachability = SCNetworkReachabilityCreateWithName(kCFAllocatorDefault, gateway);
    
    // Check if reachability created
    if (launchd_ctx.tun2socks_reachability == NULL) {
        goto fail0;
    }
    
    // Set callback
    if (!SCNetworkReachabilitySetCallback(launchd_ctx.tun2socks_reachability, tun2socks_reachability_callback, &context)) {
        goto fail1;
    }
    
    // Set dispatch queue
    if (!SCNetworkReachabilitySetDispatchQueue(launchd_ctx.tun2socks_reachability, TUN2SOCKS_REACHABILITY_QUEUE)) {
        goto fail1;
    }
    
    return 0;
    
fail1:
    CFRelease(launchd_ctx.tun2socks_reachability);
    launchd_ctx.tun2socks_reachability = NULL;
fail0:
    return -1;
}

static void launchd_force_stop(struct ev_loop *loop)
{
    // Release memory
    if (launchd_ctx.local_ctxs) {
        free(launchd_ctx.local_ctxs);
        launchd_ctx.local_ctxs = NULL;
    }
    if (launchd_ctx.pac_ctxs) {
        free(launchd_ctx.pac_ctxs);
        launchd_ctx.pac_ctxs = NULL;
    }

    // Stop tun2socks
    if (launchd_ctx.tun2socks_enabled) {
        tun2socks_route_setup(0);
        tun2socks_stop();
        launchd_ctx.tun2socks_enabled = 0;
        LOGD("tun2socks stopped.");
    }

    // Stop the loop
    LOGD("service stopped.");
    ev_break(EV_A_ EVBREAK_ALL);
}

static void signal_handler(EV_P_ struct ev_signal *w, int revents)
{
    launchd_force_stop(loop);
}

static int tun2socks_ifup(const char *ifname)
{
    struct ifreq ifr;
    struct sockaddr_in *sai;
    int sockfd;

    // Get socket fd
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        ERROR("socket");
        goto fail0;
    }

    // Copy interface name
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

    // Init socket address
    sai = (struct sockaddr_in *) &ifr.ifr_addr;
    sai->sin_family = AF_INET;

    // Set local ip address
    sai->sin_addr.s_addr = inet_addr(TUN2SOCKS_LOCAL_IP);
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        ERROR("ioctl(SIOCSIFADDR)");
        goto fail1;
    }

    // Set netmask
    sai->sin_addr.s_addr = inet_addr(TUN2SOCKS_LOCAL_NETMASK);
    if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
        ERROR("ioctl(SIOCSIFNETMASK)");
        goto fail1;
    }

    // Set local ip address again to activate netmask
    sai->sin_addr.s_addr = inet_addr(TUN2SOCKS_LOCAL_IP);
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        ERROR("ioctl(SIOCSIFADDR)");
        goto fail1;
    }

    // Set remote ip address
    sai->sin_addr.s_addr = inet_addr(TUN2SOCKS_REMOTE_IP);
    if (ioctl(sockfd, SIOCSIFDSTADDR, &ifr) < 0) {
        ERROR("ioctl(SIOCSIFDSTADDR)");
        goto fail1;
    }

    // Get flag
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        ERROR("ioctl(SIOCGIFFLAGS)");
        goto fail1;
    }

    // Set flag to up
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        ERROR("ioctl(SIOCSIFFLAGS)");
        goto fail1;
    }

    // Clean and return
    close(sockfd);
    return 0;

fail1:
    close(sockfd);
fail0:
    return -1;
}

static int tun2socks_netif_init()
{
    // Skip if already inited
    if (launchd_ctx.tun2socks_netif_inited) {
        return 0;
    }

    // Fail if tun2socks is disabled
    if (!launchd_ctx.tun2socks_enabled) {
        return -1;
    }

    // Init interface
    if (tun2socks_ifup(launchd_ctx.tun2socks_devname) == 0) {
        launchd_ctx.tun2socks_netif_inited = 1;
        return 0;
    }
    
    return -1;
}

static int find_if_with_name(const char *iface, struct sockaddr_dl *out)
{
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_dl *sdl = NULL;
    
    if (getifaddrs(&ifap)) {
        ERROR("getifaddrs");
        return -1;
    }
    
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr->sa_family == AF_LINK &&
            /*(ifa->ifa_flags & IFF_POINTOPOINT) && \ */
            strcmp(iface, ifa->ifa_name) == 0) {
            sdl = (struct sockaddr_dl *)ifa->ifa_addr;
            break;
        }
    }
    
    // If we found it, then use it
    if (sdl) {
        memcpy((char *)out, (char *)sdl, (size_t) (sdl->sdl_len));
    }
    
    freeifaddrs(ifap);
    
    if (sdl == NULL) {
        printf("interface %s not found or invalid(must be p-p)\n", iface);
        return -1;
    }
    return 0;
}

static int tun2socks_route(u_char op, in_addr_t *dst, in_addr_t *mask, in_addr_t *gateway, char *iface)
{
    
#define ROUNDUP(n)  ((n) > 0 ? (1 + (((n) - 1) | (sizeof(uint32_t) - 1))) : sizeof(uint32_t))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))
    
#define NEXTADDR(w, u) \
if (msg.msghdr.rtm_addrs & (w)) {\
len = ROUNDUP(u.sa.sa_len); memcpy(cp, (char *)&(u), len); cp += len;\
}
    
    static int seq = 0;
    int err = 0;
    ssize_t len = 0;
    char *cp;
    pid_t pid;
    
    union {
        struct sockaddr sa;
        struct sockaddr_in sin;
        struct sockaddr_dl sdl;
        struct sockaddr_storage ss;    /* added to avoid memory overrun */
    } so_addr[RTAX_MAX];
    
    struct {
        struct rt_msghdr msghdr;
        char buf[512];
    } msg;
    
    bzero(so_addr, sizeof(so_addr));
    bzero(&msg, sizeof(msg));
    
    cp = msg.buf;
    pid = getpid();
    msg.msghdr.rtm_version = RTM_VERSION;
    msg.msghdr.rtm_index = 0;
    msg.msghdr.rtm_pid = pid;
    msg.msghdr.rtm_addrs = 0;
    msg.msghdr.rtm_seq = ++seq;
    msg.msghdr.rtm_errno = 0;
    msg.msghdr.rtm_flags = 0;
    
    // Destination
    if (dst && *dst != 0xffffffff) {
        msg.msghdr.rtm_addrs |= RTA_DST;
        
        so_addr[RTAX_DST].sin.sin_len = sizeof(struct sockaddr_in);
        so_addr[RTAX_DST].sin.sin_family = AF_INET;
        so_addr[RTAX_DST].sin.sin_addr.s_addr = mask ? *dst & *mask : *dst;
    } else {
        LOGE("invalid(required) dst address.");
        return -1;
    }
    
    // Netmask
    if (mask && *mask != 0xffffffff) {
        msg.msghdr.rtm_addrs |= RTA_NETMASK;
        
        so_addr[RTAX_NETMASK].sin.sin_len = sizeof(struct sockaddr_in);
        so_addr[RTAX_NETMASK].sin.sin_family = AF_INET;
        so_addr[RTAX_NETMASK].sin.sin_addr.s_addr = *mask;
        
    } else {
        msg.msghdr.rtm_flags |= RTF_HOST;
    }
    
    switch (op) {
        case RTM_ADD:
            msg.msghdr.rtm_type = op;
            msg.msghdr.rtm_addrs |= RTA_GATEWAY;
            msg.msghdr.rtm_flags |= RTF_UP;
            
            // Gateway
            if ((gateway && *gateway != 0x0 && *gateway != 0xffffffff)) {
                msg.msghdr.rtm_flags |= RTF_GATEWAY;
                
                so_addr[RTAX_GATEWAY].sin.sin_len = sizeof(struct sockaddr_in);
                so_addr[RTAX_GATEWAY].sin.sin_family = AF_INET;
                so_addr[RTAX_GATEWAY].sin.sin_addr.s_addr = *gateway;
                
                if (iface != NULL) {
                    msg.msghdr.rtm_addrs |= RTA_IFP;
                    so_addr[RTAX_IFP].sdl.sdl_family = AF_LINK;
                    
                    //link_addr(iface, &so_addr[RTAX_IFP].sdl);
                    if (find_if_with_name(iface, &so_addr[RTAX_IFP].sdl) < 0)
                        return -2;
                }
                
            } else {
                if (iface == NULL) {
                    LOGE("Require gateway or iface.");
                    return -1;
                }
                
                if (find_if_with_name(iface, &so_addr[RTAX_GATEWAY].sdl) < 0)
                    return -1;
            }
            break;
        case RTM_DELETE:
            msg.msghdr.rtm_type = op;
            msg.msghdr.rtm_addrs |= RTA_GATEWAY;

            // Gateway
            if ((gateway && *gateway != 0x0 && *gateway != 0xffffffff)) {
                msg.msghdr.rtm_flags |= RTF_GATEWAY;

                so_addr[RTAX_GATEWAY].sin.sin_len = sizeof(struct sockaddr_in);
                so_addr[RTAX_GATEWAY].sin.sin_family = AF_INET;
                so_addr[RTAX_GATEWAY].sin.sin_addr.s_addr = *gateway;
            }
            break;
        case RTM_GET:
            msg.msghdr.rtm_type = op;
            msg.msghdr.rtm_addrs |= RTA_IFP;
            so_addr[RTAX_IFP].sa.sa_family = AF_LINK;
            so_addr[RTAX_IFP].sa.sa_len = sizeof(struct sockaddr_dl);
            break;
        default:
            return EINVAL;
    }
    
    NEXTADDR(RTA_DST, so_addr[RTAX_DST]);
    NEXTADDR(RTA_GATEWAY, so_addr[RTAX_GATEWAY]);
    NEXTADDR(RTA_NETMASK, so_addr[RTAX_NETMASK]);
    NEXTADDR(RTA_GENMASK, so_addr[RTAX_GENMASK]);
    NEXTADDR(RTA_IFP, so_addr[RTAX_IFP]);
    NEXTADDR(RTA_IFA, so_addr[RTAX_IFA]);
    
    msg.msghdr.rtm_msglen = len = cp - (char *)&msg;
    
    int sock = socket(PF_ROUTE, SOCK_RAW, AF_INET);
    if (sock < 0) {
        ERROR("socket(PF_ROUTE, SOCK_RAW, AF_INET) failed");
        return -1;
    }
    
    if (write(sock, (char *)&msg, len) < 0) {
        err = -1;
        goto end;
    }
    
    if (op == RTM_GET) {
        do {
            len = read(sock, (char *)&msg, sizeof(msg));
        } while (len > 0 && (msg.msghdr.rtm_seq != seq || msg.msghdr.rtm_pid != pid));
        
        if (len < 0) {
            ERROR("read from routing socket");
            err = -1;
        } else {
            struct sockaddr *s_dest = NULL;
            struct sockaddr *s_netmask = NULL;
            struct sockaddr *s_gate = NULL;
            struct sockaddr_dl *s_ifp = NULL;
            register struct sockaddr *sa;
            
            if (msg.msghdr.rtm_version != RTM_VERSION) {
                LOGE("routing message version %d not understood", msg.msghdr.rtm_version);
                err = -1;
                goto end;
            }
            if (msg.msghdr.rtm_msglen > len) {
                LOGE("message length mismatch, in packet %d, returned %lu\n", msg.msghdr.rtm_msglen, (unsigned long)len);
            }
            if (msg.msghdr.rtm_errno) {
                LOGE("message indicates error %d, %s\n", msg.msghdr.rtm_errno, strerror(msg.msghdr.rtm_errno));
                err = -1;
                goto end;
            }
            cp = msg.buf;
            if (msg.msghdr.rtm_addrs) {
                int i;
                for (i = 1; i; i <<= 1) {
                    if (i & msg.msghdr.rtm_addrs) {
                        sa = (struct sockaddr *)cp;
                        switch (i) {
                            case RTA_DST:
                                s_dest = sa;
                                break;
                            case RTA_GATEWAY:
                                s_gate = sa;
                                break;
                            case RTA_NETMASK:
                                s_netmask = sa;
                                break;
                            case RTA_IFP:
                                if (sa->sa_family == AF_LINK && ((struct sockaddr_dl *)sa)->sdl_nlen)
                                    s_ifp = (struct sockaddr_dl *)sa;
                                break;
                        }
                        ADVANCE(cp, sa);
                    }
                }
            }
            
            if (s_dest && msg.msghdr.rtm_flags & RTF_UP) {
                if (msg.msghdr.rtm_flags & RTF_WASCLONED) {
                    *dst = 0;
                } else {
                    *dst = ((struct sockaddr_in *)s_dest)->sin_addr.s_addr;
                }
            }
            
            if (mask) {
                if (*dst == 0) {
                    *mask = 0;
                } else if (s_netmask) {
                    *mask = ((struct sockaddr_in *)s_netmask)->sin_addr.s_addr;
                } else {
                    *mask = 0xffffffff;
                }
            }
            
            if (gateway && s_gate) {
                if (msg.msghdr.rtm_flags & RTF_GATEWAY) {
                    *gateway = ((struct sockaddr_in *)s_gate)->sin_addr.s_addr;
                } else {
                    *gateway = 0;
                }
            }
            
            if (iface && s_ifp) {
                strncpy(iface, s_ifp->sdl_data, s_ifp->sdl_nlen < IFNAMSIZ ? s_ifp->sdl_nlen : IFNAMSIZ);
                iface[IFNAMSIZ - 1] = '\0';
            }
        }
    }
    
end:
    if (close(sock) < 0) {
        ERROR("close");
    }
    
    return err;
#undef MAX_INDEX
}

static int tun2socks_route_set(int add_route, const char *ifname, const char *ipaddr, const char *netmask, const char *gateway)
{
    struct in_addr ia_ipaddr;
    struct in_addr ia_netmask;
    struct in_addr ia_gateway;
    char iface[IFNAMSIZ] = {0};
    int op = RTM_ADD;
    
    // Calculate numeric ip
    if (!inet_aton(ipaddr, &ia_ipaddr)) {
        ERROR("inet_aton(ipaddr)");
        return -1;
    }
    if (!inet_aton(netmask, &ia_netmask)) {
        ERROR("inet_aton(netmask)");
        return -1;
    }
    if (!inet_aton(gateway, &ia_gateway)) {
        ERROR("inet_aton(gateway)");
        return -1;
    }
    
    // Copy iface
    if (ifname != NULL) {
        strlcpy(iface, ifname, IFNAMSIZ);
    }
    
    // Set operation
    op = add_route ? RTM_ADD : RTM_DELETE;
    
    // Send route message
    return tun2socks_route(op, &ia_ipaddr.s_addr, &ia_netmask.s_addr, &ia_gateway.s_addr, iface);
}

static int tun2socks_route_setchnroute(int add_route, const char *ifname, const char *gateway)
{
    struct in_addr ia_gateway;
    char iface[IFNAMSIZ] = {0};
    int op = RTM_ADD;
    int ret = 0;
    int i;
    in_addr_t ipaddr;
    in_addr_t netmask;
    
    // Calculate gateway
    if (!inet_aton(gateway, &ia_gateway)) {
        ERROR("inet_aton(gateway)");
        return -1;
    }
    
    // Copy iface
    if (ifname != NULL) {
        strlcpy(iface, ifname, IFNAMSIZ);
    }
    
    // Set operation
    op = add_route ? RTM_ADD : RTM_DELETE;
    
    // Set routes
    for (i = 0; i < CHNROUTE_NUM; i++) {
        ipaddr = chnroute_ipaddr[i];
        netmask = chnroute_netmask[i];
        ret = tun2socks_route(op, &ipaddr, &netmask, &ia_gateway.s_addr, iface);
        if (ret < 0) {
            break;
        }
    }
    
    return ret;
}

static int tun2socks_route_gateway_get()
{
    struct in_addr ia_ipaddr;
    struct in_addr ia_netmask;
    struct in_addr ia_gateway;
    char iface[IFNAMSIZ] = {0};
    int err = 0;
    
    // Set ip
    ia_ipaddr.s_addr = INADDR_ANY;
    ia_netmask.s_addr = INADDR_ANY;
    ia_gateway.s_addr = INADDR_ANY;
    
    // Send route message
    err = tun2socks_route(RTM_GET, &ia_ipaddr.s_addr, &ia_netmask.s_addr, &ia_gateway.s_addr, iface);
    if (err < 0) {
        return -1;
    }
    
    // Save gateway and iface
    strlcpy(launchd_ctx.tun2socks_gateway, inet_ntoa(ia_gateway), sizeof(launchd_ctx.tun2socks_gateway));
    strlcpy(launchd_ctx.tun2socks_iface, iface, sizeof(launchd_ctx.tun2socks_iface));
    
    return 0;
}

static int tun2socks_route_setup(int add_route)
{
    int err = 0;
    int remote_addr_is_ipv4 = 0;
    size_t remote_addr_len;
    size_t remote_addr_span;
    const char *opinfo = add_route ? TUN2SOCKS_INFO_ADD : TUN2SOCKS_INFO_REMOVE;
    
    // Init network interface
    if (tun2socks_netif_init() < 0) {
        LOGE("failed to init netif.");
        return -1;
    }
    
    // Resolve and monitor current default gateway when adding routes
    if (add_route) {
        err = tun2socks_route_gateway_get();
        if (err) {
            if (verbose) {
                LOGE("failed to resolve current gateway.");
            }
            // Use default wifi gateway instead
            tun2socks_reachability_register(1, TUN2SOCKS_REACHABILITY_WIFI_GATEWAY);
            
            // Skipping route settings
            return -1;
        } else {
            tun2socks_reachability_register(1, launchd_ctx.tun2socks_gateway);
        }
    } else {
        tun2socks_reachability_register(0, NULL);
    }

    // Test if remote addr is ipv4
    remote_addr_is_ipv4 = 0;
    remote_addr_span = strspn(launchd_ctx.remote_addr, TUN2SOCKS_IPV4_ADDR_CHARSET);
    remote_addr_len = strlen(launchd_ctx.remote_addr);

    if (remote_addr_span == remote_addr_len) {
        remote_addr_is_ipv4 = 1;
    } else {
        struct addrinfo hints;
        struct addrinfo *res;
        struct addrinfo *rp;

        // Get remote addr info
        memset(&hints, 0, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;    
        err = getaddrinfo(launchd_ctx.remote_addr, NULL, &hints, &res);
        if (err) {
            ERROR("getaddrinfo");
        } else {
            // Get remote addr numeric ip
            char remote_hostname[INET6_ADDRSTRLEN] = {0};
            for (rp = res; rp; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET) {
                    err = getnameinfo(rp->ai_addr, rp->ai_addrlen, remote_hostname, INET6_ADDRSTRLEN, NULL, 0, NI_NUMERICHOST); 
                    if (err == 0) {
                        remote_addr_is_ipv4 = 1;
                        strlcpy(launchd_ctx.remote_addr, remote_hostname, sizeof(launchd_ctx.remote_addr));
                        break;
                    }
                }
            }
        }
    }

    if (remote_addr_is_ipv4) {
        // Except remote addr in route 
        if (tun2socks_route_set(add_route, launchd_ctx.tun2socks_iface, launchd_ctx.remote_addr, "255.255.255.255", launchd_ctx.tun2socks_gateway)) {
            if (verbose) {
                LOGE("failed to %s route of remote addr.", opinfo);
            }
        }
    }
    
    int add_chnroute = launchd_ctx.tun2socks_chnroute;
    
    // Remove chnroutes if not enabled
    if (!launchd_ctx.tun2socks_chnroute) {
        add_chnroute = 0;
    }
    
    // Except all chnroutes
    if (tun2socks_route_setchnroute(add_chnroute, launchd_ctx.tun2socks_iface, launchd_ctx.tun2socks_gateway)) {
        if (verbose && launchd_ctx.tun2socks_chnroute) {
            LOGE("failed to %s chnroutes.", opinfo);
        }
    }
    
    // Set new default gateway
    if (tun2socks_route_set(add_route, launchd_ctx.tun2socks_devname, "0.0.0.0", "128.0.0.0", TUN2SOCKS_REMOTE_IP)) {
        if (verbose) {
            LOGE("failed to %s default route.", opinfo);
        }
    }
    if (tun2socks_route_set(add_route, launchd_ctx.tun2socks_devname, "128.0.0.0", "128.0.0.0", TUN2SOCKS_REMOTE_IP)) {
        if (verbose) {
            LOGE("failed to %s route 128.0.0.0.", opinfo);
        }
    }
    
    // Set google public dns
    if (!launchd_get_proxy_dict(0, 0, 1, add_route)) {
        if (verbose) {
            LOGE("failed to %s dns", opinfo);
        }
    }

    return 0;
}

static int tun2socks_get_utunnum(void)
{
    struct ifaddrs *ifap;
    struct ifaddrs *ifa;
    int max_utunnum = -1;
    int utunnum = -1;
    char *name;
    char *s;
    char *t;

    if (getifaddrs(&ifap) != 0) {
        ERROR("getifaddrs(utunnum)");
        return 0;
    }
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        name = ifa->ifa_name;
        if (name && strstr(name, TUN2SOCKS_DEV_NAME)) {
            s = name + sizeof(TUN2SOCKS_DEV_NAME) - 1;
            t = s;
            utunnum = (int) strtol(s, &t, 10);
            if (s == t) {
                utunnum = -1;
            }
            if (utunnum > max_utunnum) {
                max_utunnum = utunnum;
            }
        }
    }
    freeifaddrs(ifap);
    return max_utunnum + 1;
}

static void tun2socks_init(void (^success)(void), void (^fail)(void))
{
    // Ignore if already inited
    if (launchd_ctx.tun2socks_inited) {
        if (launchd_ctx.tun2socks_enabled) {
            if (success) {
                success();
            }
        } else {
            LOGE("tun2socks not enabled.");
            if (fail) {
                fail();
            }
        }
        return;
    }
    
    // Set resource limit
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) != 0) {
        LOGE("failed to get resource limit");
    } else {
        rl.rlim_cur = TUN2SOCKS_RLIMIT_NOFILE;
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) {
            LOGE("failed to set resource limit");
        }
    }
    
    // Initialize tun2socks in thread
    dispatch_queue_t queue = dispatch_queue_create(TUN2SOCKS_QUEUE_NAME, NULL);
    dispatch_async(queue, ^{
        char *argv[TUN2SOCKS_ARGC + 1] = {
            TUN2SOCKS_APP_NAME,
            "--tundev", TUN2SOCKS_ARG_STUB, // 2 - tundev
            "--socks-server-addr", TUN2SOCKS_ARG_STUB, // 4 - server_addr
            "--netif-ipaddr", TUN2SOCKS_REMOTE_IP,
            "--netif-netmask", TUN2SOCKS_NETMASK,
            "--loglevel", TUN2SOCKS_ARG_STUB, // 10 - log level
            "--enable-udprelay",
            NULL
        };
        char tundev[TUN2SOCKS_ARG_MAXLEN] = {0};
        char server_addr[TUN2SOCKS_ARG_MAXLEN] = {0};
        int utunnum = 0;
        int ret = 0;

        // Get available utun device name
        utunnum = tun2socks_get_utunnum();
        snprintf(tundev, TUN2SOCKS_ARG_MAXLEN, TUN2SOCKS_DEV_NAME "%d", utunnum);
        argv[2] = tundev;
        strlcpy(launchd_ctx.tun2socks_devname, tundev, sizeof(launchd_ctx.tun2socks_devname));

        // Concat addr with port
        snprintf(server_addr, TUN2SOCKS_ARG_MAXLEN, "127.0.0.1:%s", launchd_ctx.local_port);
        argv[4] = server_addr;

        // Set log level
        argv[10] = verbose ? TUN2SOCKS_LOG_VERBOSE : TUN2SOCKS_LOG_NONE;

        // Start tun2socks
        ret = tun2socks_start(TUN2SOCKS_ARGC, argv, ^{
            launchd_ctx.tun2socks_enabled = 1;
            launchd_ctx.tun2socks_inited = 1;
            if (success) {
                success();
            }
        });
        if (ret != 0) {
            LOGE("failed to init tun2socks.");
            launchd_ctx.tun2socks_enabled = 0;
            launchd_ctx.tun2socks_inited = 1;
            if (fail) {
                fail();
            }
        }
    });
    dispatch_release(queue);
}
#endif

static void pac_recv_cb (EV_P_ ev_io *w, int revents)
{
    char use_pac;
    char exception_sent;
    char found_pac_func;
    int len;
    int sent_num;
    int except_str_len;
    int i;

    FILE *pacfile;
    char *buf;
    char *now_buf;
    char *pac_func_name;
    char *pac_except_start;
    char *except_str;
    char *p;
    struct pac_server_ctx *pac;

    // Set pac context
    pac = (struct pac_server_ctx *) w;
    if (pac == NULL) {
        LOGE("pac context is null");
        return;
    } else if (pac->buf == NULL) {
        LOGE("buffer of pac context is null");
        return;
    }

    // Set receive buffer
    buf = pac->buf;
    buf[0] = 0;

    // Receive and parse HTTP request
    len = recv(pac->fd, buf, BUF_SIZE - 1, 0);
    if (len == 0) {
        close_and_free_pac(EV_A_ pac);
        return;
    } else if (len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            ERROR("pac recv");
            close_and_free_pac(EV_A_ pac);
        }
        return;
    }
    buf[len] = '\0';

    // Send HTTP response header
    SEND_CONST_STR(pac->fd, PAC_RESPONSE);

#ifdef __APPLE__
    // Respond to launchd commands
    if (launchd || udprelay) {
        int will_update;
        int will_force_stop;
        int will_set_proxy;
        int will_set_vpn;
        int proxy_enabled;
        int proxy_socks;
        int vpn_enabled;
        int vpn_auto;
        char *proxy_type;
        char *vpn_type;

        will_update = 0;
        will_force_stop = 0;
        will_set_proxy = 0;
        will_set_vpn = 0;
        proxy_enabled = 0;
        proxy_socks = 0;
        vpn_enabled = 0;
        vpn_auto = 0;
        proxy_type = PAC_SET_PROXY_NONE;
        vpn_type = PAC_SET_VPN_NONE;

        if (strstr(buf, PAC_UPDATE_CONF)) {
            will_update = 1;
        } else if (strstr(buf, PAC_FORCE_STOP)) {
            will_force_stop = 1;
        } else if (strstr(buf, PAC_SET_PROXY_NONE)) {
            will_set_proxy = 1;
            proxy_enabled = 0;
            proxy_type = PAC_SET_PROXY_NONE;
        } else if (strstr(buf, PAC_SET_PROXY_SOCKS)) {
            will_set_proxy = 1;
            proxy_enabled = 1;
            proxy_socks = 1;
            proxy_type = PAC_SET_PROXY_SOCKS;
        } else if (strstr(buf, PAC_SET_PROXY_PAC)) {
            will_set_proxy = 1;
            proxy_enabled = 1;
            proxy_socks = 0;
            proxy_type = PAC_SET_PROXY_PAC;
        } else if (strstr(buf, PAC_SET_VPN_NONE)) {
            will_set_vpn = 1;
            vpn_enabled = 0;
            vpn_type = PAC_SET_VPN_NONE;
        } else if (strstr(buf, PAC_SET_VPN_ALL)) {
            will_set_vpn = 1;
            vpn_enabled = 1;
            vpn_auto = 0;
            vpn_type = PAC_SET_VPN_ALL;
        } else if (strstr(buf, PAC_SET_VPN_AUTO)) {
            will_set_vpn = 1;
            vpn_enabled = 1;
            vpn_auto = 1;
            vpn_type = PAC_SET_VPN_AUTO;
        }

        do {
            if (will_update) {
                launchd_reload_conf();
                SEND_CONST_STR(pac->fd, PAC_RESPONSE_SUCC);
            } else if (will_force_stop) {
                SEND_CONST_STR(pac->fd, PAC_RESPONSE_SUCC);
            } else if (will_set_proxy) {
                if (launchd_get_proxy_dict(proxy_enabled, proxy_socks, 0, 0)) {
                    SEND_CONST_STR(pac->fd, PAC_RESPONSE_SUCC);
                    if (verbose) {
                        LOGD("proxy is set: %s.", proxy_type);
                    }
                } else {
                    SEND_CONST_STR(pac->fd, PAC_RESPONSE_FAIL);
                    if (verbose) {
                        LOGE("failed to set proxy: %s.", proxy_type);
                    }
                }
            } else if (will_set_vpn) {
                if (vpn_enabled == 0 && !launchd_ctx.tun2socks_enabled) {
                    SEND_CONST_STR(pac->fd, PAC_RESPONSE_SUCC);
                    close_and_free_pac(EV_A_ pac);
                    if (verbose) {
                        LOGD("vpn is set: %s.", vpn_type);
                    }
                } else {
                    tun2socks_init(^{
                        launchd_ctx.tun2socks_chnroute = vpn_auto;
                        if (tun2socks_route_setup(vpn_enabled) == 0) {
                            SEND_CONST_STR(pac->fd, PAC_RESPONSE_SUCC);
                            if (verbose) {
                                LOGD("vpn is set: %s.", vpn_type);
                            }
                        } else {
                            SEND_CONST_STR(pac->fd, PAC_RESPONSE_FAIL);
                            if (verbose) {
                                LOGE("failed to set vpn: %s.", vpn_type);
                            }
                        }
                        close_and_free_pac(EV_A_ pac);
                    }, ^{
                        SEND_CONST_STR(pac->fd, PAC_RESPONSE_FAIL);
                        close_and_free_pac(EV_A_ pac);
                        if (verbose) {
                            LOGE("failed to set vpn: %s.", vpn_type);
                        }
                    });
                }
                return;
            } else {
                break;
            }
            close_and_free_pac(EV_A_ pac);
            if (will_force_stop) {
                launchd_force_stop(loop);
            }
            return;
        } while (0);
    }
#endif

    // Generate exception list
    except_str = NULL;
    except_str_len = 0;
    if (launchd_ctx.except_num > 0) {
        except_str_len = PAC_EXCEPT_HEAD_LEN + launchd_ctx.except_num * PAC_EXCEPT_ENTRY_LEN;
        for (i = 0; i < launchd_ctx.except_num; i++) {
            except_str_len += 2 * strlen(launchd_ctx.except_list[i]);
        }
        except_str = (char *) malloc(except_str_len + 1);
        strncpy(except_str, PAC_EXCEPT_HEAD, PAC_EXCEPT_HEAD_LEN);
        p = except_str + PAC_EXCEPT_HEAD_LEN;
        for (i = 0; i < launchd_ctx.except_num; i++) {
            p += sprintf(p, PAC_EXCEPT_ENTRY, launchd_ctx.except_list[i], launchd_ctx.except_list[i]);
        }
    }

    // Send pac file content
    use_pac = 0;
    if (launchd_ctx.pac_path != NULL) {
        if ((pacfile = fopen(launchd_ctx.pac_path, "r")) != NULL) {
            use_pac = 1;
            exception_sent = 0;
            found_pac_func = 0;
            while ((len = fread(buf, 1, BUF_SIZE - 1, pacfile)) > 0) {
                buf[len] = 0;
                now_buf = buf;
                if (!exception_sent) {
                    pac_func_name = strstr(buf, PAC_FUNC_NAME);
                    if (pac_func_name || found_pac_func) {
                        if (pac_func_name) {
                            found_pac_func = 1;
                        } else {
                            pac_func_name = buf;
                        }
                        pac_except_start = strchr(pac_func_name, '{');
                        if (pac_except_start) {
                            sent_num = (pac_except_start - buf) + 1;
                            send(pac->fd, buf, sent_num, 0);
                            if (except_str_len > 0) {
                                send(pac->fd, except_str, except_str_len, 0);
                            }
                            exception_sent = 1;
                            now_buf += sent_num;
                            len -= sent_num;
                        }
                    }
                }
                if (len > 0) {
                    send(pac->fd, now_buf, len, 0);
                }
            }
            fclose(pacfile);
        }
    }

    // Send default pac content
    if (!use_pac) {
        buf = pac->buf;
        buf[0] = '\0';
        len = 0;

        SEND_CONST_STR(pac->fd, PAC_DEFAULT_HEAD);
        if (except_str_len > 0) {
            send(pac->fd, except_str, except_str_len, 0);
        }

        if (launchd_ctx.except_ios) {
            len = sprintf(buf, PAC_DEFAULT_TAIL_IOS, launchd_ctx.local_port);
        } else {
            len = sprintf(buf, PAC_DEFAULT_TAIL, launchd_ctx.local_port, launchd_ctx.local_port);
        }
        if (len > 0 && len < BUF_SIZE) {
            buf[len] = '\0';
            send(pac->fd, buf, len, 0);
        }
    }

    // Free exception string
    if (except_str) {
        free(except_str);
        except_str = NULL;
        except_str_len = 0;
    }

    // Close and free context
    close_and_free_pac(EV_A_ pac);
}

static void pac_accept_cb(EV_P_ ev_io *w, int revents)
{
    struct pac_server_ctx *listener = (struct pac_server_ctx *) w;
    int serverfd;
    socklen_t socksize;
    struct sockaddr_in client;
    struct pac_server_ctx *pac;

    memset(&client, 0, sizeof(client));
    socksize = sizeof(struct sockaddr_in);
    serverfd = accept(listener->fd, (struct sockaddr *) &client, &socksize);
    if (serverfd < 0) {
        ERROR("accept for pac");
        return;
    }
    setnonblocking(serverfd);
    pac = (struct pac_server_ctx *) malloc(sizeof(struct pac_server_ctx));
    pac->buf = (char *) malloc(BUF_SIZE);
    pac->fd = serverfd;
    ev_io_init(&pac->io, pac_recv_cb, serverfd, EV_READ);  
    ev_io_start(EV_A_ &pac->io);
}

void close_and_free_pac(EV_P_ struct pac_server_ctx *ctx)
{
    if (ctx) {
        ev_io_stop(EV_A_ &ctx->io);
        close(ctx->fd);
        if (ctx->buf) {
            free(ctx->buf);
            ctx->buf = NULL;
        }
        free(ctx);
    }
}

int main (int argc, char **argv)
{

    int i, c;
    int pid_flags = 0;
    char *user = NULL;
    char *local_port = NULL;
    char *local_addr = NULL;
    char *password = NULL;
    char *timeout = NULL;
    char *method = NULL;
    char *pid_path = NULL;
    char *conf_path = NULL;
    char *iface = NULL;
    char *pac_port = NULL;
    char *pac_path = NULL;

    int remote_num = 0;
    ss_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    int except_ios = 0;
    int except_num = 0;
    except_addr_t except_list[MAX_EXCEPT_NUM];

    opterr = 0;

    while ((c = getopt (argc, argv, "f:s:p:l:k:t:m:i:c:b:a:x:y:e:dnuv")) != -1)
    {
        switch (c)
        {
        case 's':
            if (remote_num < MAX_REMOTE_NUM) {
                remote_addr[remote_num].host = optarg;
                remote_addr[remote_num++].port = NULL;
            }
            break;
        case 'p':
            remote_port = optarg;
            break;
        case 'l':
            local_port = optarg;
            break;
        case 'k':
            password = optarg;
            break;
        case 'f':
            pid_flags = 1;
            pid_path = optarg;
            break;
        case 't':
            timeout = optarg;
            break;
        case 'm':
            method = optarg;
            break;
        case 'c':
            conf_path = optarg;
            break;
        case 'i':
            iface = optarg;
            break;
        case 'b':
            local_addr = optarg;
            break;
        case 'a':
            user = optarg;
            break;
        case 'x':
            pac_port = optarg;
            break;
        case 'y':
            pac_path = optarg;
            break;
        case 'e':
            if (except_num < MAX_EXCEPT_NUM) {
                except_list[except_num++] = optarg;
            }
            break;
        case 'd':
            launchd = 1;
            break;
        case 'n':
            except_ios = 1;
            break;
        case 'u':
            udprelay = 1;
            break;
        case 'v':
            verbose = 1;
            break;
        }
    }

    if (opterr)
    {
        usage();
        exit(EXIT_FAILURE);
    }

    if (conf_path != NULL)
    {
        jconf_t *conf = read_jconf(conf_path);
        if (remote_num == 0)
        {
            remote_num = conf->remote_num;
            for (i = 0; i < remote_num; i++)
            {
                remote_addr[i] = conf->remote_addr[i];
            }
        }
        if (except_num == 0) {
            except_num = conf->except_num;
            for (i = 0; i < except_num; i++) {
                except_list[i] = conf->except_list[i];
            }
        }
        if (remote_port == NULL) remote_port = conf->remote_port;
        if (local_addr == NULL) local_addr = conf->local_addr;
        if (local_port == NULL) local_port = conf->local_port;
        if (password == NULL) password = conf->password;
        if (method == NULL) method = conf->method;
        if (timeout == NULL) timeout = conf->timeout;
        if (pac_port == NULL) pac_port = conf->pac_port;
        if (pac_path == NULL) pac_path = conf->pac_path;
    } else if (launchd) {
        FATAL("config file is required in launchd mode");
    }

    if (remote_num == 0 || remote_port == NULL ||
            local_port == NULL || password == NULL)
    {
        if (launchd) {
            LOGE("missing parameters.");
        } else {
            usage();
        }
        exit(EXIT_FAILURE);
    }

    if (pac_port != NULL && strcmp(pac_port, local_port) == 0) {
        FATAL("local port and pac port should be different.");
    }

    if (timeout == NULL) timeout = "10";

    if (local_addr == NULL) local_addr = "0.0.0.0";

    if (pid_flags && !launchd)
    {
        USE_SYSLOG(argv[0]);
        demonize(pid_path);
    }

#ifdef __MINGW32__
    winsock_init();
#else
    // ignore SIGPIPE
    signal(SIGPIPE, SIG_IGN);
    signal(SIGABRT, SIG_IGN);
#endif

    // Setup keys
    LOGD("initialize ciphers... %s", method);
    int m = enc_init(password, method);

    // Save config for global use
    launchd_ctx.conf_path = conf_path;
    launchd_ctx.cipher_mode = m;
    launchd_ctx.except_ios = except_ios;
    launchd_ctx.except_num = except_num;
    launchd_ctx.except_list = except_list;
    launchd_ctx.pac_path = pac_path;
    launchd_ctx.pac_port = pac_port;
    strlcpy(launchd_ctx.local_port, local_port, sizeof(launchd_ctx.local_port));
    strlcpy(launchd_ctx.remote_addr, remote_addr[0].host, sizeof(launchd_ctx.remote_addr));
    strlcpy(launchd_ctx.remote_port, remote_port, sizeof(launchd_ctx.remote_port));
    save_str(&launchd_ctx.password, strdup(password));
    save_str(&launchd_ctx.method, strdup(method));

    // Reset tun2socks running status
    launchd_ctx.tun2socks_enabled = 0;
    launchd_ctx.tun2socks_inited = 0;
    launchd_ctx.tun2socks_netif_inited = 0;
    launchd_ctx.tun2socks_chnroute = 0;
    memset(launchd_ctx.tun2socks_gateway, 0, sizeof(launchd_ctx.tun2socks_gateway));
    launchd_ctx.tun2socks_reachability = NULL;

    // Setup libev loop
    struct ev_loop *loop = ev_default_loop(0);
    if (!loop) {
        FATAL("ev_loop error.");
    }

#ifdef __APPLE__
    // Bind signal handler
    struct ev_signal signal_watcher_int;
    struct ev_signal signal_watcher_term;
    ev_signal_init(&signal_watcher_int, signal_handler, SIGINT);
    ev_signal_init(&signal_watcher_term, signal_handler, SIGTERM);
    ev_signal_start(loop, &signal_watcher_int);
    ev_signal_start(loop, &signal_watcher_term);
#endif

    if (launchd) {
#ifdef __APPLE__
        launch_data_t sockets_dict;
        launch_data_t checkin_response;
        launch_data_t checkin_request;
        launch_data_t listening_fd_array;
        launch_data_t this_listening_fd;
        int listen_ok;
        int i;
        int found_legal_fd;
        struct listen_ctx *p_listen_ctx;
        struct pac_server_ctx *p_pac_ctx;

        // Setup for launchd mode
        do {
            listen_ok = -1;
            if ((checkin_request = launch_data_new_string(LAUNCH_KEY_CHECKIN)) == NULL) {
                LOGE("launch_data_new_string error");
                break;
            }
            if ((checkin_response = launch_msg(checkin_request)) == NULL) {
                LOGE("launch_msg error");
                break;
            }
            listen_ok = 0;
            if (LAUNCH_DATA_ERRNO == launch_data_get_type(checkin_response)) {
                LOGE("check-in failed");
                break;
            }
            sockets_dict = launch_data_dict_lookup(checkin_response, LAUNCH_JOBKEY_SOCKETS);
            if (NULL == sockets_dict) {
                LOGE("no sockets found to answer requests on");
                break;
            }

            // Setup for local socks port
            listening_fd_array = launch_data_dict_lookup(sockets_dict, LAUNCHD_NAME_SOCKS);
            if (NULL == listening_fd_array) {
                LOGE("no %s entry found in plist", LAUNCHD_NAME_SOCKS);
                break;
            }
            launchd_ctx.local_ctxs_len = launch_data_array_get_count(listening_fd_array);
            if (launchd_ctx.local_ctxs_len <= 0) {
                LOGE("no socks fd found from launchd");
                break;
            }
            launchd_ctx.local_ctxs = (struct listen_ctx *) malloc(sizeof(struct listen_ctx) * launchd_ctx.local_ctxs_len);
            found_legal_fd = 0;
            for (i = 0; i < launchd_ctx.local_ctxs_len; i++) {
                p_listen_ctx = &launchd_ctx.local_ctxs[i];
                this_listening_fd = launch_data_array_get_index(listening_fd_array, i);
                p_listen_ctx->fd = launch_data_get_fd(this_listening_fd);
                if (p_listen_ctx->fd >= 0) {
                    conf_listen_ctx(p_listen_ctx, remote_num, remote_port, remote_addr, timeout, iface, m);
                    ev_io_init(&p_listen_ctx->io, accept_cb, p_listen_ctx->fd, EV_READ);
                    ev_io_start(EV_A_ &p_listen_ctx->io);
                    if (!found_legal_fd) {
                        found_legal_fd = 1;
                    }
                }
            }
            if (!found_legal_fd) {
                free(launchd_ctx.local_ctxs);
                launchd_ctx.local_ctxs = NULL;
                LOGE("no legal socks fd found from launchd");
                break;
            }

            // Setup for pac port
            if (pac_port != NULL) {
                listening_fd_array = launch_data_dict_lookup(sockets_dict, LAUNCHD_NAME_PAC);
                if (NULL == listening_fd_array) {
                    LOGE("no %s entry found in plist", LAUNCHD_NAME_PAC);
                    break;
                }
                launchd_ctx.pac_ctxs_len = launch_data_array_get_count(listening_fd_array);
                if (launchd_ctx.pac_ctxs_len <= 0) {
                    LOGE("no pac fd found from launchd");
                    break;
                }
                launchd_ctx.pac_ctxs = (struct pac_server_ctx *) malloc(sizeof(struct pac_server_ctx) * launchd_ctx.pac_ctxs_len);
                found_legal_fd = 0;
                for (i = 0; i < launchd_ctx.pac_ctxs_len; i++) {
                    p_pac_ctx = &launchd_ctx.pac_ctxs[i];
                    this_listening_fd = launch_data_array_get_index(listening_fd_array, i);
                    p_pac_ctx->fd = launch_data_get_fd(this_listening_fd);
                    if (p_pac_ctx->fd >= 0) {
                        ev_io_init(&p_pac_ctx->io, pac_accept_cb, p_pac_ctx->fd, EV_READ);
                        ev_io_start(EV_A_ &p_pac_ctx->io);
                        if (!found_legal_fd) {
                            found_legal_fd = 1;
                        } 
                    }
                }
                if (!found_legal_fd) {
                    free(launchd_ctx.pac_ctxs);
                    launchd_ctx.pac_ctxs = NULL;
                    LOGE("no legal socks fd found from launchd");
                    break;
                }
            }

            // Setup succeed
            listen_ok = 1;
        } while (0);

        if (listen_ok >= 0) {
            launch_data_free(checkin_response);
            launch_data_free(checkin_request);
        }
        if (listen_ok != 1) {
            FATAL("failed to start by launchd");
        }
        LOGD("running in launchd mode...");
#else
        FATAL("launchd mode is only for darwin.");
#endif

    } else {

        // Setup socket
        int listenfd;
        listenfd = create_and_bind(local_addr, local_port);
        if (listenfd < 0)
        {
            FATAL("bind() error.");
        }
        if (listen(listenfd, SOMAXCONN) == -1)
        {
            FATAL("listen() error.");
        }
        setnonblocking(listenfd);
        LOGD("server listening at port %s.", local_port);

        // Setup proxy context
        struct listen_ctx listen_ctx;
        listen_ctx.fd = listenfd;
        conf_listen_ctx(&listen_ctx, remote_num, remote_port, remote_addr, timeout, iface, m);

        ev_io_init (&listen_ctx.io, accept_cb, listenfd, EV_READ);
        ev_io_start (loop, &listen_ctx.io);

        // Setup pac server
        if (pac_port != NULL) {
            struct pac_server_ctx pac_ctx;
            int pacfd;

            pacfd = create_and_bind(local_addr, pac_port);
            if (pacfd < 0) {
                FATAL("bind error for pac.");
            }
            if (listen(pacfd, SOMAXCONN) == -1) {
                FATAL("listen error for pac.");
            }
            setnonblocking(pacfd);
            pac_ctx.fd = pacfd;
            ev_io_init(&pac_ctx.io, pac_accept_cb, pacfd, EV_READ);
            ev_io_start(EV_A_ &pac_ctx.io);

            LOGD("pac server listening at port %s.", pac_port);
        }
    }

    // Setup UDP
    if (udprelay) {
        LOGD("udprelay enabled.");
#ifdef __APPLE__
        udprelay_init(local_addr, launchd_ctx.local_port, launchd_ctx.remote_addr, launchd_ctx.remote_port, m, atoi(timeout), iface);
#else
        udprelay_init(local_addr, local_port, remote_addr[0].host, remote_addr[0].port, m, atoi(timeout), iface);
#endif
    }

    // setuid
    if (user != NULL)
        run_as(user);

    // Start loop
    ev_run (loop, 0);

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    return 0;
}


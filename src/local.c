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
#include <CoreFoundation/CoreFoundation.h>
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
ev_timer launchd_timer;

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
            char *addr_to_send = malloc(BUF_SIZE);
            ssize_t addr_len = 0;
            addr_to_send[addr_len++] = request->atyp;

            // get remote addr and port
            if (request->atyp == 1)
            {
                // IP V4
                size_t in_addr_len = sizeof(struct in_addr);
                memcpy(addr_to_send + addr_len, remote->buf + 4, in_addr_len + 2);
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
                addr_to_send[addr_len++] = name_len;
                memcpy(addr_to_send + addr_len, remote->buf + 4 + 1, name_len + 2);
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
                memcpy(addr_to_send + addr_len, remote->buf + 4, in6_addr_len + 2);
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

            addr_to_send = ss_encrypt(BUF_SIZE, addr_to_send, &addr_len, server->e_ctx);
            if (addr_to_send == NULL)
            {
                LOGE("invalid password or cipher");
                close_and_free_remote(EV_A_ remote);
                close_and_free_server(EV_A_ server);
                return;
            }
            int s = send(remote->fd, addr_to_send, addr_len, 0);
            free(addr_to_send);

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

    LOGD("remote timeout");

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
#ifdef __APPLE__
    if (launchd) {
        ev_timer_again(EV_A_ &launchd_timer);
    }
#endif
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

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0)
    {
        ERROR("socket");
        close(sockfd);
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
    char *remote_port, remote_addr_t *remote_addr, char *timeout, char *iface, int m)
{
    int index = 0;

    p_listen_ctx->remote_num = remote_num;
    p_listen_ctx->remote_addr = remote_addr;
    while (remote_num > 0) {
        index = --remote_num;
        if (remote_addr[index].port == NULL) {
            remote_addr[index].port = remote_port;
        }
    }
    p_listen_ctx->timeout = atoi(timeout);
    p_listen_ctx->iface = iface;
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
            LOGD("reloading ciphers... %s", conf->method);
        }
        launchd_ctx.except_num = conf->except_num;
        launchd_ctx.except_list = conf->except_list;
        launchd_ctx.pac_port = conf->pac_port;
        launchd_ctx.pac_path = conf->pac_path;
        launchd_ctx.local_port = conf->local_port;
        for (i = 0; i < launchd_ctx.local_ctxs_len; i++) {
            conf_listen_ctx(&launchd_ctx.local_ctxs[i], conf->remote_num, conf->remote_port, \
                conf->remote_addr, conf->timeout, NULL, launchd_ctx.cipher_mode);
        }
        LOGD("config reloaded.");
    }
}

static int launchd_set_proxy(CFDictionaryRef proxyDict)
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

static int launchd_get_proxy_dict(int enabled, int is_socks)
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
    ret = launchd_set_proxy(proxyDict);
    CFRelease(proxyDict);
    return ret;
}

static void launchd_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    LOGD("launchd timeout, stopping service...");

    // Release memory
    if (launchd_ctx.local_ctxs) {
        free(launchd_ctx.local_ctxs);
        launchd_ctx.local_ctxs = NULL;
    }
    if (launchd_ctx.pac_ctxs) {
        free(launchd_ctx.pac_ctxs);
        launchd_ctx.pac_ctxs = NULL;
    }

    // Stop the loop
    ev_break(EV_A_ EVBREAK_ALL);
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

    FILE *stream;
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

    // Open received data as stream
    stream = fdopen(pac->fd, "w");
    if (stream == NULL) {
        ERROR("fdopen");
        close_and_free_pac(EV_A_ pac);
        return;
    }

    // Send HTTP response header
    fprintf(stream, PAC_RESPONSE);

#ifdef __APPLE__
    // Respond to launchd commands
    if (launchd) {
        int will_update;
        int will_set_proxy;
        int proxy_enabled;
        int proxy_socks;
        char *proxy_type;

        will_update = 0;
        will_set_proxy = 0;
        proxy_enabled = 0;
        proxy_socks = 0;

        if (strstr(buf, PAC_UPDATE_CONF)) {
            will_update = 1;
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
        }

        do {
            if (will_update) {
                launchd_reload_conf();
                fprintf(stream, PAC_RESPONSE_SUCC);
            } else if (will_set_proxy) {
                if (launchd_get_proxy_dict(proxy_enabled, proxy_socks)) {
                    fprintf(stream, PAC_RESPONSE_SUCC);
                    LOGD("proxy is set: %s.", proxy_type);
                } else {
                    fprintf(stream, PAC_RESPONSE_FAIL);
                    LOGE("failed to set proxy: %s.", proxy_type);
                }
            } else {
                break;
            }
            fflush(stream);
            fclose(stream);
            close_and_free_pac(EV_A_ pac);
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
                            fwrite(buf, 1, sent_num, stream);
                            if (except_str_len > 0) {
                                fwrite(except_str, 1, except_str_len, stream);
                            }
                            exception_sent = 1;
                            now_buf += sent_num;
                            len -= sent_num;
                        }
                    }
                }
                if (len > 0) {
                    fwrite(now_buf, 1, len, stream);
                }       
            }
            fclose(pacfile);
        }
    }

    // Send default pac content
    if (!use_pac) {
        fprintf(stream, PAC_DEFAULT_HEAD);
        if (except_str_len > 0) {
            fwrite(except_str, 1, except_str_len, stream);
        }
        if (launchd_ctx.except_ios) {
            fprintf(stream, PAC_DEFAULT_TAIL_IOS, launchd_ctx.local_port);
        } else {
            fprintf(stream, PAC_DEFAULT_TAIL, launchd_ctx.local_port, launchd_ctx.local_port);
        }
    }

    // Free exception string
    if (except_str) {
        free(except_str);
        except_str = NULL;
        except_str_len = 0;
    }

    // Close stream and free context
    fflush(stream);
    fclose(stream);
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
#ifdef __APPLE__
    if (launchd) {
        ev_timer_again(EV_A_ &launchd_timer);
    }
#endif
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
    int launchd_timeout = 0;
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
    remote_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port = NULL;

    int except_ios = 0;
    int except_num = 0;
    except_addr_t except_list[MAX_EXCEPT_NUM];

    opterr = 0;

    while ((c = getopt (argc, argv, "f:s:p:l:k:t:m:i:c:b:x:y:e:d:nuv")) != -1)
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
            launchd_timeout = atoi(optarg);
            if (launchd_timeout == 0) {
                launchd_timeout = LAUNCHD_DEFAULT_TIMEOUT;
            }
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
    launchd_ctx.local_port = local_port;
    save_str(&launchd_ctx.password, strdup(password));
    save_str(&launchd_ctx.method, strdup(method));

    // Setup libev loop
    struct ev_loop *loop = ev_default_loop(0);
    if (!loop) {
        FATAL("ev_loop error.");
    }

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

        // Start launchd auto exit timer
        ev_timer_init(&launchd_timer, launchd_timeout_cb, 0, launchd_timeout);
        ev_timer_again(EV_A_ &launchd_timer);
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

        // Setup UDP
        if (udprelay) {
            LOGD("udprelay enabled.");
            udprelay_init(local_addr, local_port, remote_addr[0].host, remote_addr[0].port, m, listen_ctx.timeout, iface);
        }
    }

    // Start loop
    ev_run (loop, 0);

#ifdef __MINGW32__
    winsock_cleanup();
#endif

    return 0;
}


#ifndef _LOCAL_H
#define _LOCAL_H

#include <ev.h>
#include "encrypt.h"
#include "jconf.h"
#include "include.h"

#define PAC_RESPONSE "HTTP/1.1 200 OK\r\nServer: shadowsocks pac server\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nConnection: close\r\n\r\n"
#define PAC_FUNC_NAME "FindProxyForURL"
#define PAC_DEFAULT_HEAD "function FindProxyForURL(url, host) {\n"
#define PAC_DEFAULT_TAIL "    if (host == '127.0.0.1' || host == 'localhost')\n        return 'DIRECT'\n    return 'SOCKS5 127.0.0.1:%s; SOCKS 127.0.0.1:%s';\n}\n"
#define PAC_DEFAULT_TAIL_IOS "    if (host == '127.0.0.1' || host == 'localhost')\n        return 'DIRECT'\n    return 'SOCKS 127.0.0.1:%s';\n}\n"
#define PAC_EXCEPT_HEAD "\n    var lhost = host.toLowerCase();\n"
#define PAC_EXCEPT_ENTRY "    if (shExpMatch(lhost, '%s')) return 'DIRECT';\n    if (shExpMatch(lhost, '*.%s')) return 'DIRECT';\n"
#define PAC_EXCEPT_HEAD_LEN (sizeof(PAC_EXCEPT_HEAD) - 1)
#define PAC_EXCEPT_ENTRY_LEN (sizeof(PAC_EXCEPT_ENTRY) - 5)
#define PAC_UPDATE_CONF "Update-Conf"
#define PAC_SET_PROXY_PAC "SetProxy-Pac"
#define PAC_SET_PROXY_SOCKS "SetProxy-Socks"
#define PAC_SET_PROXY_NONE "SetProxy-None"
#define PAC_RESPONSE_SUCC "Updated.\n"
#define PAC_RESPONSE_FAIL "Failed.\n"

#define LAUNCHD_NAME_SOCKS "SOCKS"
#define LAUNCHD_NAME_PAC "PAC"
#define LAUNCHD_DEFAULT_TIMEOUT 480

struct listen_ctx
{
    ev_io io;
    remote_addr_t *remote_addr;
    char *iface;
    int remote_num;
    int method;
    int timeout;
    int fd;
    struct sockaddr sock;
};

struct server_ctx
{
    ev_io io;
    int connected;
    struct server *server;
};

struct pac_server_ctx
{
    ev_io io;
    int fd;
    char *buf;
};

struct server
{
    int fd;
    int buf_len;
    int buf_idx;
    char *buf; // server send from, remote recv into
    char stage;
    struct enc_ctx *e_ctx;
    struct enc_ctx *d_ctx;
    struct server_ctx *recv_ctx;
    struct server_ctx *send_ctx;
    struct remote *remote;
};

struct remote_ctx
{
    ev_io io;
    ev_timer watcher;
    int connected;
    struct remote *remote;
};

struct remote
{
    int fd;
    int buf_len;
    int buf_idx;
    char *buf; // remote send from, server recv into
    struct remote_ctx *recv_ctx;
    struct remote_ctx *send_ctx;
    struct server *server;
};

typedef struct {
    int local_ctxs_len;
    struct listen_ctx *local_ctxs;
    int pac_ctxs_len;
    struct pac_server_ctx *pac_ctxs;
    char *conf_path;
    char *pac_path;
    char *pac_port;
    char *local_port;
    int except_ios;
    int except_num;
    except_addr_t *except_list;
    int cipher_mode;
    char *method;
    char *password;
} launchd_ctx_t;

static void accept_cb (EV_P_ ev_io *w, int revents);
static void server_recv_cb (EV_P_ ev_io *w, int revents);
static void server_send_cb (EV_P_ ev_io *w, int revents);
static void remote_recv_cb (EV_P_ ev_io *w, int revents);
static void remote_send_cb (EV_P_ ev_io *w, int revents);
static void pac_accept_cb (EV_P_ ev_io *w, int revents);
static void pac_recv_cb (EV_P_ ev_io *w, int revents);
static void launchd_timeout_cb(EV_P_ ev_timer *w, int revents);
static void free_remote(struct remote *remote);
static void close_and_free_remote(EV_P_ struct remote *remote);
static void free_server(struct server *server);
static void close_and_free_server(EV_P_ struct server *server);
static void close_and_free_pac(EV_P_ struct pac_server_ctx *ctx);

struct remote* new_remote(int fd, int timeout);
struct server* new_server(int fd, int method);

int udprelay_init(const char *server_host, const char *server_port,
             const char *remote_host, const char *remote_port,
             int method, const char *interface_name);

#ifdef __APPLE__
typedef const struct __SCPreferences *  SCPreferencesRef;
SCPreferencesRef SCPreferencesCreate (CFAllocatorRef allocator, CFStringRef name, CFStringRef prefsID);
typedef const struct __SCDynamicStore * SCDynamicStoreRef;
typedef void (*SCDynamicStoreCallBack) (SCDynamicStoreRef store, CFArrayRef changedKeys, void *info);
typedef struct {
    CFIndex     version;
    void *      info;
    const void  *(*retain)(const void *info);
    void        (*release)(const void *info);
    CFStringRef (*copyDescription)(const void *info);
} SCDynamicStoreContext;
SCDynamicStoreRef SCDynamicStoreCreate (CFAllocatorRef allocator, CFStringRef name, SCDynamicStoreCallBack callout, SCDynamicStoreContext *context);
CFPropertyListRef SCPreferencesGetValue(SCPreferencesRef prefs, CFStringRef key);
Boolean SCPreferencesPathSetValue (SCPreferencesRef prefs, CFStringRef path, CFDictionaryRef value);
Boolean SCPreferencesCommitChanges (SCPreferencesRef prefs);
Boolean SCPreferencesApplyChanges (SCPreferencesRef prefs);
void SCPreferencesSynchronize (SCPreferencesRef prefs);
#endif

#endif // _LOCAL_H

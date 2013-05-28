#include <Foundation/Foundation.h>
#include <launch.h>
#include "../src/local.h"
#include "../src/utils.h"

#define REMOTE_TIMEOUT 10
#define LOCAL_TIMEOUT 60
#define BUFF_MAX 1024
#define LOCAL_PORT 1983
#define PAC_PORT 1993
#define EMPTY_PAC_HEAD "function FindProxyForURL(url, host) {\n"

#ifdef DARWIN_MAC
#define PREF_FILE @"/Users/Shared/.com.linusyang.ShadowSocks.plist"
#define EMPTY_PAC_TAIL "    if (host == '127.0.0.1' || host == 'localhost')\n        return 'DIRECT'\n    return 'SOCKS5 127.0.0.1:%d; SOCKS 127.0.0.1:1983';\n}\n"
#else
#define PREF_FILE @"/var/mobile/Library/Preferences/com.linusyang.MobileShadowSocks.plist"
#define EMPTY_PAC_TAIL "    if (host == '127.0.0.1' || host == 'localhost')\n        return 'DIRECT'\n    return 'SOCKS 127.0.0.1:%d';\n}\n"
#endif

#define HTTP_RESPONSE "HTTP/1.1 200 OK\r\nServer: Pac HTTP Server\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nConnection: close\r\n\r\n"
#define UPDATE_CONF "Update-Conf"
#define SET_PROXY_PAC "SetProxy-Pac"
#define SET_PROXY_SOCKS "SetProxy-Socks"
#define SET_PROXY_NONE "SetProxy-None"
#define LAUNCHD_NAME_SOCKS "SOCKS"
#define LAUNCHD_NAME_PAC "PAC"
#define PAC_FUNC "FindProxyForURL"
#define PAC_EXCEPT_HEAD "\n    var lhost = host.toLowerCase();\n"
#define PAC_EXCEPT_ENTRY @"    if (shExpMatch(lhost, '%@')) return 'DIRECT';\n    if (shExpMatch(lhost, '*.%@')) return 'DIRECT';\n"

typedef void (*ev_handler)(struct ev_loop *, struct ev_io *, int);

struct pac_server_ctx {
    ev_io io;
    int fd;
    char *buf;
};

void update_config();
void update_ctx_conf(struct listen_ctx *ctx);
void update_ctx_array_conf(struct listen_ctx *ctx_array, int array_len);
struct listen_ctx *listen_from_launchd(EV_P_ int *array_len, const char *socket_name, launch_data_t sockets_dict, ev_handler handler);
int listen_from_port(EV_P_ struct listen_ctx *ctx, int port, ev_handler handler);
static void pac_accept_cb (EV_P_ ev_io *w, int revents);
static void listen_timeout_cb(EV_P_ ev_timer *watcher, int revents);
int create_and_bind(const char *port);
int setnonblocking(int fd);

typedef enum {kProxyPac, kProxySocks, kProxyNone} ProxyStatus;
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

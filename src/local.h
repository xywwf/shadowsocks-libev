#ifndef _LOCAL_H
#define _LOCAL_H

#include <ev.h>
#include "encrypt.h"
#include "jconf.h"
#include "include.h"

#ifdef __APPLE__

#ifdef __OSX_AVAILABLE_STARTING
#undef __OSX_AVAILABLE_STARTING
#define __OSX_AVAILABLE_STARTING(...)
#endif
#include <SystemConfiguration/SystemConfiguration.h>

#endif

#define SEND_CONST_STR(fd, s) (send(fd, s, (sizeof(s) - 1), 0))

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
#define PAC_FORCE_STOP "Force-Stop"
#define PAC_SET_PROXY_PAC "SetProxy-Pac"
#define PAC_SET_PROXY_SOCKS "SetProxy-Socks"
#define PAC_SET_PROXY_NONE "SetProxy-None"
#define PAC_SET_VPN_ALL "SetVPN-All"
#define PAC_SET_VPN_AUTO "SetVPN-Auto"
#define PAC_SET_VPN_NONE "SetVPN-None"
#define PAC_RESPONSE_SUCC "Updated.\n"
#define PAC_RESPONSE_FAIL "Failed.\n"

#define TUN2SOCKS_ARG_MAXLEN 60
#define TUN2SOCKS_ARGC 12
#define TUN2SOCKS_ARG_STUB ""
#define TUN2SOCKS_APP_NAME "tun2socks"
#define TUN2SOCKS_QUEUE_NAME "com.linusyang." TUN2SOCKS_APP_NAME
#define TUN2SOCKS_DEV_NAME "utun"
#define TUN2SOCKS_REMOTE_IP "10.8.4.1"
#define TUN2SOCKS_LOCAL_IP "10.8.4.2"
#define TUN2SOCKS_NETMASK "255.255.255.0"
#define TUN2SOCKS_LOCAL_NETMASK "255.255.255.255"
#define TUN2SOCKS_LOG_NONE "0"
#define TUN2SOCKS_LOG_VERBOSE "4"
#define TUN2SOCKS_IPV4_ADDR_CHARSET ".0123456789"
#define TUN2SOCKS_RLIMIT_NOFILE 8192
#define TUN2SOCKS_REACHABILITY_QUEUE (dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0))
#define TUN2SOCKS_REACHABILITY_WIFI_GATEWAY "169.254.0.0"
#define TUN2SOCKS_INFO_ADD "add"
#define TUN2SOCKS_INFO_REMOVE "remove"

#define LAUNCHD_NAME_SOCKS "SOCKS"
#define LAUNCHD_NAME_PAC "PAC"
#define LAUNCHD_CTX_BUFSIZE 50

struct listen_ctx
{
    ev_io io;
#ifndef __APPLE__
    ss_addr_t *remote_addr;
    char *iface;
    int remote_num;
#endif
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
    char local_port[LAUNCHD_CTX_BUFSIZE];
    int except_ios;
    int except_num;
    except_addr_t *except_list;
    int cipher_mode;
    char *method;
    char *password;
    char remote_addr[LAUNCHD_CTX_BUFSIZE];
    char remote_port[LAUNCHD_CTX_BUFSIZE];
    int tun2socks_enabled;
    int tun2socks_inited;
    int tun2socks_netif_inited;
    int tun2socks_chnroute;
    char tun2socks_devname[LAUNCHD_CTX_BUFSIZE];
    char tun2socks_gateway[LAUNCHD_CTX_BUFSIZE];
    char tun2socks_iface[LAUNCHD_CTX_BUFSIZE];
#ifdef __APPLE__
    SCNetworkReachabilityRef tun2socks_reachability;
#endif
} launchd_ctx_t;

static void accept_cb (EV_P_ ev_io *w, int revents);
static void server_recv_cb (EV_P_ ev_io *w, int revents);
static void server_send_cb (EV_P_ ev_io *w, int revents);
static void remote_recv_cb (EV_P_ ev_io *w, int revents);
static void remote_send_cb (EV_P_ ev_io *w, int revents);
static void pac_accept_cb (EV_P_ ev_io *w, int revents);
static void pac_recv_cb (EV_P_ ev_io *w, int revents);
static void free_remote(struct remote *remote);
static void close_and_free_remote(EV_P_ struct remote *remote);
static void free_server(struct server *server);
static void close_and_free_server(EV_P_ struct server *server);
static void close_and_free_pac(EV_P_ struct pac_server_ctx *ctx);

struct remote* new_remote(int fd, int timeout);
struct server* new_server(int fd, int method);

#ifdef __APPLE__

// tun2socks
void tun2socks_stop(void);
int tun2socks_start(int argc, char **argv, void (^handler)(void));
static int tun2socks_route_setup(int add_route);

// simplified chnroutes
#define CHNROUTE_NUM 978
static const in_addr_t chnroute_ipaddr[CHNROUTE_NUM] = {
    0x000c01, 0x001801, 0x002d01, 0x003001, 0x003801, 0x004401, 0x007401, 0x00b401,
    0x00b801, 0x00bc01, 0x00c001, 0x00ca01, 0x00cc01, 0x00081b, 0x00101b, 0x00241b,
    0x00281b, 0x80321b, 0xc0361b, 0xd0621b, 0xe0621b, 0x24641b, 0x00671b, 0x806a1b,
    0x00701b, 0x50701b, 0x00801b, 0xdc831b, 0x00901b, 0x00941b, 0x00981b, 0x00b81b,
    0x00c01b, 0x00e01b, 0x000e3a, 0x00103a, 0x00183a, 0x001e3a, 0x00203a, 0x00423a,
    0x80443a, 0x00523a, 0x40573a, 0x80633a, 0x00643a, 0x00743a, 0x00803a, 0x00903a,
    0x009a3a, 0x00c03a, 0x00f03a, 0x00203b, 0x00403b, 0x00503b, 0x006b3b, 0x006c3b,
    0x00973b, 0x009b3b, 0x00ac3b, 0x00bf3b, 0xf0bf3b, 0x00c03b, 0x00003c, 0x00373c,
    0x003f3c, 0x00a03c, 0x00c23c, 0x00c83c, 0x00d03c, 0x00e83c, 0x00eb3c, 0x80f53c,
    0x00f73c, 0x00fc3c, 0x80fd3c, 0x00ff3c, 0x40043d, 0xb0043d, 0xa0083d, 0x001c3d,
    0x801d3d, 0x802d3d, 0x802f3d, 0x00303d, 0xc0573d, 0x00803d, 0x00e83d, 0x00ec3d,
    0x00f03d, 0x00066e, 0x00106e, 0x00286e, 0x00306e, 0x00336e, 0x00346e, 0x00386e,
    0x00406e, 0x00486e, 0x004b6e, 0x004c6e, 0xc04c6e, 0x004d6e, 0x00506e, 0x00586e,
    0x005e6e, 0x00606e, 0x00986e, 0x009c6e, 0x20a56e, 0x00a66e, 0xc0ac6e, 0x00ad6e,
    0x20ad6e, 0x40ad6e, 0xc0ad6e, 0x00b06e, 0x00c06e, 0x00e46e, 0x20e86e, 0x00ec6e,
    0x00f06e, 0x00006f, 0x00426f, 0xc0436f, 0x40446f, 0x00486f, 0x00556f, 0xc05b6f,
    0x00706f, 0x00746f, 0x40776f, 0x80776f, 0x00786f, 0x007c6f, 0x007e6f, 0x00806f,
    0x00a06f, 0x00aa6f, 0x00ac6f, 0x00b06f, 0x00ba6f, 0x00c06f, 0x00d06f, 0x80dd6f,
    0x00de6f, 0xf0df6f, 0xf8df6f, 0x00e06f, 0x60eb6f, 0xa0eb6f, 0x000070, 0x004070,
    0x004970, 0x004a70, 0x005070, 0x006070, 0x806d70, 0x006f70, 0x007070, 0x007470,
    0x007a70, 0x007c70, 0x008070, 0x008470, 0x00c070, 0x00e070, 0x000071, 0x000871,
    0xc00b71, 0x000c71, 0x001071, 0x001271, 0x001871, 0x001f71, 0x002c71, 0x003071,
    0xa03471, 0x003671, 0x003871, 0x003a71, 0x003b71, 0x003e71, 0x004071, 0x008071,
    0x608271, 0x708271, 0x008471, 0x008871, 0x00c271, 0x00c871, 0x00ca71, 0x00cc71,
    0x60d071, 0x80d071, 0x00d171, 0x00d471, 0x00d571, 0x00d671, 0x00da71, 0x00dc71,
    0x00e071, 0x00f071, 0x00f871, 0x001c72, 0x003672, 0x003c72, 0x004072, 0x004472,
    0x005072, 0x006072, 0x006872, 0x006e72, 0x406e72, 0x806e72, 0x006f72, 0xa06f72,
    0x007072, 0x008472, 0x008772, 0x008a72, 0x808d72, 0x00c472, 0x00d072, 0x00e072,
    0x001873, 0x001c73, 0x002073, 0x002c73, 0x003073, 0x005473, 0xc05473, 0xc05573,
    0x006473, 0x006873, 0x007873, 0x107c73, 0x009473, 0x009873, 0x00a873, 0x00b473,
    0x00c073, 0x00e073, 0x000174, 0x000274, 0x000474, 0x000874, 0x000d74, 0x001074,
    0x003474, 0x003874, 0x803a74, 0xd03a74, 0x003c74, 0x004274, 0x004574, 0x004674,
    0x004c74, 0x905974, 0x505a74, 0xb85a74, 0x005f74, 0x007074, 0x007474, 0x008074,
    0x00c074, 0x10c174, 0x20c174, 0x00c274, 0x00c474, 0x00c674, 0x00c774, 0x80c774,
    0x00cc74, 0x00cf74, 0x00d074, 0xa0d474, 0x40d574, 0x80d574, 0x20d674, 0x40d674,
    0x80d674, 0x00d774, 0x00d874, 0x00e074, 0x00f274, 0x00f474, 0x00f874, 0x00fc74,
    0x80fe74, 0x80ff74, 0x000875, 0x001575, 0x001675, 0x001875, 0x002075, 0x002875,
    0x002c75, 0x003075, 0x303575, 0xb03575, 0x003975, 0x003a75, 0x003b75, 0x003c75,
    0x004075, 0x004875, 0x404a75, 0x804a75, 0x004b75, 0x004c75, 0x005075, 0x006475,
    0x106775, 0x806775, 0x006a75, 0x007075, 0x407875, 0x807875, 0x007975, 0x807975,
    0xc07975, 0x807a75, 0x007c75, 0x008075, 0x001876, 0x004076, 0x004276, 0x704376,
    0x004876, 0x005076, 0x005476, 0x205876, 0x405876, 0x805876, 0x005976, 0xf05b76,
    0x106676, 0x007076, 0x007876, 0x007c76, 0x007e76, 0x008476, 0x009076, 0x00b276,
    0x00b476, 0x00b876, 0x00c076, 0x00d476, 0x00e076, 0x00e476, 0x00e676, 0x00ef76,
    0x00f276, 0x00f476, 0x00f876, 0x000077, 0x000277, 0x800277, 0x000377, 0x000477,
    0x000877, 0x000a77, 0x880f77, 0x001077, 0xc01277, 0xd01277, 0xe01277, 0x001377,
    0x001477, 0x401b77, 0xa01b77, 0xc01b77, 0x001c77, 0x301e77, 0xc01f77, 0x002077,
    0x002877, 0x402877, 0x802877, 0x002977, 0x002a77, 0x882a77, 0xe02a77, 0x002c77,
    0x003077, 0x003977, 0x003a77, 0x803b77, 0x003c77, 0x003e77, 0x203f77, 0xd04b77,
    0x004e77, 0x005077, 0x005477, 0x005877, 0x006077, 0x006c77, 0x007077, 0x008077,
    0x009077, 0xa09477, 0x80a177, 0x00a277, 0x00a477, 0x00b077, 0x00e877, 0x80eb77,
    0x00f877, 0x00fd77, 0x00fe77, 0x000078, 0x001878, 0x001e78, 0x002078, 0x003078,
    0x003478, 0x004078, 0x204878, 0x804878, 0x004c78, 0x005078, 0x085878, 0x005a78,
    0x005c78, 0x005e78, 0x008078, 0x808878, 0x008978, 0x00c078, 0x100079, 0x000479,
    0x000879, 0x001079, 0x002079, 0x002879, 0x002e79, 0x003079, 0x003379, 0xa03479,
    0xd03479, 0xe03479, 0x003779, 0x003879, 0x003a79, 0x903a79, 0x003b79, 0x003c79,
    0x004479, 0x004c79, 0x804f79, 0x005979, 0x806479, 0xd06579, 0x00c079, 0x00c979,
    0x00cc79, 0x00e079, 0x00f879, 0x00ff79, 0x40007a, 0x80007a, 0x00047a, 0x00087a,
    0x00307a, 0x00317a, 0x00337a, 0x00407a, 0x00607a, 0x00667a, 0x40667a, 0x00707a,
    0x00777a, 0x00887a, 0x80907a, 0xc0987a, 0x009c7a, 0x00c07a, 0x00c67a, 0x40c87a,
    0x00cc7a, 0x00e07a, 0x00f07a, 0x30f87a, 0x80007b, 0x00047b, 0x00087b, 0x80317b,
    0x00347b, 0x00387b, 0x00407b, 0x00607b, 0x00627b, 0x80637b, 0x00647b, 0x00657b,
    0x00677b, 0x806c7b, 0xd06c7b, 0x00707b, 0x00807b, 0x50887b, 0x00897b, 0x008a7b,
    0x00907b, 0x00a07b, 0x50b07b, 0x00b17b, 0x00b27b, 0x00b47b, 0x00b87b, 0x00c47b,
    0x80c77b, 0x00ce7b, 0x00e87b, 0x00f27b, 0x00f47b, 0x00f97b, 0x00fd7b, 0x40067c,
    0x000e7c, 0x00107c, 0x00147c, 0xc01c7c, 0x001d7c, 0x001f7c, 0x70287c, 0x80287c,
    0x002a7c, 0x002f7c, 0x00407c, 0x00427c, 0x00437c, 0x00447c, 0x00487c, 0x00587c,
    0x086c7c, 0x286c7c, 0x00707c, 0x007e7c, 0x00807c, 0x80937c, 0x00977c, 0x009c7c,
    0x00a07c, 0x00ac7c, 0x00c07c, 0x00c47c, 0x00c87c, 0x00dc7c, 0x00e07c, 0x00f07c,
    0x80f07c, 0x00f27c, 0xc0f37c, 0x00f87c, 0x00f97c, 0x00fa7c, 0x00fe7c, 0xc01f7d,
    0x00207d, 0x803a7d, 0x803d7d, 0x003e7d, 0x00407d, 0x00607d, 0x00627d, 0x00687d,
    0x00707d, 0x00a97d, 0x00ab7d, 0x00d07d, 0x00d27d, 0x00d57d, 0x60d67d, 0x00d77d,
    0x00d87d, 0x80fe7d, 0x00c486, 0x00e29f, 0x00cfa1, 0x0069a2, 0x006fa6, 0x008ba7,
    0x00a0a8, 0x0000af, 0x0010af, 0x0018af, 0x001eaf, 0x002aaf, 0x002caf, 0x002eaf,
    0x0030af, 0x0040af, 0x0066af, 0x806aaf, 0x0092af, 0x0094af, 0x0098af, 0x00a0af,
    0x00b2af, 0x80b8af, 0x00b9af, 0x00baaf, 0x00bcaf, 0x004cb4, 0x0054b4, 0x0056b4,
    0x0058b4, 0x385eb4, 0x605eb4, 0x805fb4, 0x0060b4, 0x8081b4, 0x0082b4, 0x0088b4,
    0xe094b4, 0x8095b4, 0xa096b4, 0x0098b4, 0x00a0b4, 0xc0b2b4, 0x00b8b4, 0x00bcb4,
    0x94bdb4, 0xfcc8b4, 0x00c9b4, 0x00cab4, 0x00d0b4, 0xe0d2b4, 0x00d4b4, 0xe0deb4,
    0x00dfb4, 0x00e9b4, 0x40e9b4, 0x40ebb4, 0xc010b6, 0x0012b6, 0x0020b6, 0x6030b6,
    0x0031b6, 0x0032b6, 0x7032b6, 0x0033b6, 0x0036b6, 0x003db6, 0x0050b6, 0x0058b6,
    0x005cb6, 0x0060b6, 0x0080b6, 0x0090b6, 0x009db6, 0x40a0b6, 0x00aeb6, 0x00c8b6,
    0x80ecb6, 0x00eeb6, 0x00efb6, 0x00f0b6, 0x00feb6, 0x0000b7, 0x0040b7, 0xb451b7,
    0x0054b7, 0x805bb7, 0x905bb7, 0x005cb7, 0x0080b7, 0x00a0b7, 0x00a8b7, 0x00aab7,
    0x00acb7, 0x00b6b7, 0x00b8b7, 0x00c0b7, 0x7a53c0, 0xa953c0, 0x9a7cc0, 0xaabcc0,
    0x0711c6, 0x6e00ca, 0xb000ca, 0x8004ca, 0xfc04ca, 0x8008ca, 0x400aca, 0x580eca,
    0xeb0eca, 0xec0eca, 0xee0eca, 0x7814ca, 0xf816ca, 0x0026ca, 0x4026ca, 0x8026ca,
    0x8826ca, 0x8a26ca, 0x8c26ca, 0x9026ca, 0x9526ca, 0x9626ca, 0x9826ca, 0x9c26ca,
    0x9e26ca, 0xa026ca, 0xa426ca, 0xa826ca, 0xb026ca, 0xb826ca, 0xc026ca, 0x9829ca,
    0xf029ca, 0x4c2bca, 0x902bca, 0x202eca, 0xe02eca, 0x703cca, 0xf83fca, 0x0445ca,
    0x1045ca, 0x0046ca, 0x084aca, 0xd04bca, 0xd055ca, 0x005aca, 0xe05aca, 0xfc5aca,
    0x005bca, 0x805bca, 0xb05bca, 0xe05bca, 0x005cca, 0xfc5cca, 0x005dca, 0xfc5dca,
    0x005eca, 0x005fca, 0xfc5fca, 0x0060ca, 0x0070ca, 0x0078ca, 0x007aca, 0x207aca,
    0x407aca, 0x707aca, 0x807aca, 0x607bca, 0x187cca, 0xb07dca, 0x007fca, 0x0c7fca,
    0x107fca, 0x287fca, 0x307fca, 0x707fca, 0x807fca, 0xa07fca, 0xc07fca, 0xd07fca,
    0xd87fca, 0xe07fca, 0x0082ca, 0xe082ca, 0x1083ca, 0x3083ca, 0xd083ca, 0x3088ca,
    0xd088ca, 0xe088ca, 0xfc88ca, 0xa08dca, 0x108eca, 0x108fca, 0x6094ca, 0xa095ca,
    0xe095ca, 0x1096ca, 0xb098ca, 0x3099ca, 0xa09eca, 0xb0a0ca, 0x00a4ca, 0x19a4ca,
    0x60a5ca, 0xb0a5ca, 0xd0a5ca, 0xa0a8ca, 0x80aaca, 0xd8aaca, 0x08adca, 0xe0adca,
    0xf0b3ca, 0x80b4ca, 0x70b5ca, 0x50bdca, 0x00c0ca, 0x3212cb, 0x304ecb, 0x004fcb,
    0x9050cb, 0x1051cb, 0x3853cb, 0x0056cb, 0x4056cb, 0x2058cb, 0xc058cb, 0x0059cb,
    0x005acb, 0x805acb, 0xc05acb, 0x205bcb, 0x605bcb, 0x785bcb, 0x005ccb, 0xa05ccb,
    0x005dcb, 0x005ecb, 0x005fcb, 0x605fcb, 0x1063cb, 0x5063cb, 0x2064cb, 0x5064cb,
    0x6064cb, 0xc064cb, 0xa06ecb, 0xf472cb, 0xc076cb, 0xf876cb, 0x1877cb, 0x2077cb,
    0x5077cb, 0x2080cb, 0x6080cb, 0x8080cb, 0x2082cb, 0x2084cb, 0xf086cb, 0x6087cb,
    0xa087cb, 0xdb8ecb, 0x0094cb, 0x4098cb, 0xc09ccb, 0x109ecb, 0xb4a1cb, 0xc0a1cb,
    0xa0a6cb, 0xe0abcb, 0x07aecb, 0x60aecb, 0x80afcb, 0xc0afcb, 0xa8b0cb, 0x50b8cb,
    0xa0bbcb, 0x60becb, 0x10bfcb, 0x40bfcb, 0x90bfcb, 0x00c0cb, 0x00c4cb, 0x40cfcb,
    0x80cfcb, 0x00d0cb, 0x10d0cb, 0x20d0cb, 0xe0d1cb, 0x00d4cb, 0x50d4cb, 0xc0decb,
    0x00dfcb, 0x0002d2, 0x0005d2, 0x8005d2, 0x000cd2, 0x400ed2, 0x700ed2, 0x800ed2,
    0x000fd2, 0x800fd2, 0x8010d2, 0x0015d2, 0x0016d2, 0x2017d2, 0x0019d2, 0x001ad2,
    0x001cd2, 0x0020d2, 0x0033d2, 0x0034d2, 0xc038d2, 0x0048d2, 0x004cd2, 0x004ed2,
    0x404fd2, 0xe04fd2, 0x0052d2, 0x8057d2, 0xc0b9d2, 0x60c0d2, 0x00d3d2, 0x0040d3,
    0x0050d3, 0x0060d3, 0x0088d3, 0x0090d3, 0x00a0d3, 0x0000da, 0x0038da, 0x0040da,
    0x0060da, 0x0068da, 0x006cda, 0xc0b9da, 0x00c0da, 0x00f0da, 0x00f9da, 0x0048db,
    0x0052db, 0x0080db, 0x00d8db, 0x00e0db, 0x00f2db, 0x00f4db, 0xc065dc, 0x0070dc,
    0x8098dc, 0x009adc, 0x00a0dc, 0x00c0dc, 0x00e7dc, 0x80e7dc, 0x40e8dc, 0x00eadc,
    0x00f2dc, 0x00f8dc, 0x00fcdc, 0x0000dd, 0x0008dd, 0x000cdd, 0x800cdd, 0x000ddd,
    0x000edd, 0x007add, 0x0081dd, 0x0082dd, 0xe085dd, 0x0088dd, 0x00acdd, 0x00b0dd,
    0x00c0dd, 0x00c4dd, 0x00c6dd, 0x00c7dd, 0x80c7dd, 0xc0c7dd, 0xe0c7dd, 0x00c8dd,
    0x00d0dd, 0x00e0dd, 0x0010de, 0x0020de, 0x0040de, 0x007dde, 0x807ede, 0x0080de,
    0x00a0de, 0x00a8de, 0x00b0de, 0x00c0de, 0x00f0de, 0x00f8de, 0x0008df, 0x0010df,
    0x0020df, 0x0040df
};
static const in_addr_t chnroute_netmask[CHNROUTE_NUM] = {
    0x00fcff, 0x00f8ff, 0x00ffff, 0x00feff, 0x00f8ff, 0x00fcff, 0x00fcff, 0x00fcff,
    0x00feff, 0x00fcff, 0x00f8ff, 0x00feff, 0x00fcff, 0x00f8ff, 0x00f0ff, 0x00fcff,
    0x00f8ff, 0x80ffff, 0xc0ffff, 0xf0ffff, 0xe0ffff, 0xfcffff, 0x00ffff, 0xc0ffff,
    0xc0ffff, 0xf0ffff, 0x00feff, 0xfcffff, 0x00ffff, 0x00fcff, 0x00f8ff, 0x00f8ff,
    0x00e0ff, 0x00fcff, 0x00feff, 0x00f8ff, 0x00feff, 0x00feff, 0x00e0ff, 0x00feff,
    0x80ffff, 0x00feff, 0xc0ffff, 0x80ffff, 0x00feff, 0x00fcff, 0x00f8ff, 0x00ffff,
    0x00feff, 0x00e0ff, 0x00f0ff, 0x00e0ff, 0x00f0ff, 0x00fcff, 0x00ffff, 0x00fcff,
    0x80ffff, 0x00ffff, 0x00fcff, 0x80ffff, 0xf0ffff, 0x00c0ff, 0x00e0ff, 0x00ffff,
    0x00ffff, 0x00e0ff, 0x00feff, 0x00f8ff, 0x00f0ff, 0x00feff, 0x00ffff, 0x80ffff,
    0x00ffff, 0x00ffff, 0x80ffff, 0x00ffff, 0xe0ffff, 0xf0ffff, 0xf0ffff, 0x80ffff,
    0x80ffff, 0xc0ffff, 0xc0ffff, 0x00f8ff, 0xc0ffff, 0x00c0ff, 0x00fcff, 0x00feff,
    0x00fcff, 0x00feff, 0x00fcff, 0x00fcff, 0x00ffff, 0x00ffff, 0x00feff, 0x00f8ff,
    0x00feff, 0x00feff, 0x00ffff, 0xc0ffff, 0xc0ffff, 0x80ffff, 0x00f8ff, 0x00fcff,
    0x00feff, 0x00e0ff, 0x00fcff, 0x00feff, 0xe0ffff, 0x00feff, 0xc0ffff, 0xe0ffff,
    0xf0ffff, 0xc0ffff, 0xe0ffff, 0x00f0ff, 0x00e0ff, 0x00fcff, 0xe0ffff, 0x00feff,
    0x00f0ff, 0x00c0ff, 0x00ffff, 0xf0ffff, 0xe0ffff, 0x00f8ff, 0x00ffff, 0xe0ffff,
    0x00fcff, 0x00feff, 0xc0ffff, 0xe0ffff, 0x00fcff, 0x00ffff, 0x00feff, 0x00e0ff,
    0x00f8ff, 0x00ffff, 0x00fcff, 0x00f8ff, 0x00feff, 0x00f0ff, 0x00f8ff, 0x80ffff,
    0x00ffff, 0xfcffff, 0xfcffff, 0x00f8ff, 0xe0ffff, 0xe0ffff, 0x00c0ff, 0x00fcff,
    0x00ffff, 0x00feff, 0x00f0ff, 0x00f8ff, 0x80ffff, 0x00ffff, 0x00fcff, 0x00feff,
    0x00feff, 0x00fcff, 0x00fcff, 0x00ffff, 0x00fcff, 0x00e0ff, 0x00f8ff, 0x00feff,
    0xe0ffff, 0x00fcff, 0x00feff, 0x00ffff, 0x00fcff, 0x00ffff, 0x00fcff, 0x00fcff,
    0xe0ffff, 0x00feff, 0x00feff, 0x00ffff, 0x80ffff, 0x00feff, 0x00c0ff, 0x00feff,
    0xf0ffff, 0xf8ffff, 0x00fcff, 0x00f8ff, 0x00feff, 0x00feff, 0x00ffff, 0x00fcff,
    0xe0ffff, 0x80ffff, 0x00ffff, 0xc0ffff, 0x80ffff, 0x00feff, 0x00feff, 0x00fcff,
    0x00f0ff, 0x00f8ff, 0x00fcff, 0x00ffff, 0x00feff, 0x00fcff, 0x00fcff, 0x00ffff,
    0x00f0ff, 0x00f8ff, 0x00fcff, 0xf0ffff, 0xc0ffff, 0x80ffff, 0xe0ffff, 0xe0ffff,
    0x00f8ff, 0x00ffff, 0x00ffff, 0x00feff, 0xc0ffff, 0x00feff, 0x00f0ff, 0x00e0ff,
    0x00fcff, 0x00feff, 0x00fcff, 0x00fcff, 0x00f0ff, 0xc0ffff, 0xe0ffff, 0xc0ffff,
    0x00fcff, 0x00fcff, 0x00fcff, 0xf0ffff, 0x00fcff, 0x00f8ff, 0x00f8ff, 0x00fcff,
    0x00e0ff, 0x00f0ff, 0x00ffff, 0x00feff, 0x00fcff, 0x00fcff, 0x00ffff, 0x00f0ff,
    0x00fcff, 0x00feff, 0xf0ffff, 0xf0ffff, 0x00fcff, 0x80ffff, 0x00ffff, 0x80ffff,
    0x00fcff, 0xf0ffff, 0xf0ffff, 0xf8ffff, 0x00ffff, 0x00fcff, 0x00feff, 0x00c0ff,
    0x00ffff, 0xf0ffff, 0xe0ffff, 0x00feff, 0x00ffff, 0x00ffff, 0x80ffff, 0xe0ffff,
    0x00feff, 0x00ffff, 0x00fcff, 0xf0ffff, 0xc0ffff, 0x80ffff, 0xe0ffff, 0xf0ffff,
    0x80ffff, 0x00ffff, 0x00fcff, 0x00f0ff, 0x00feff, 0x00fcff, 0x00feff, 0x00feff,
    0x80ffff, 0x80ffff, 0x00f8ff, 0x00ffff, 0x00feff, 0x00f8ff, 0x00f8ff, 0x00fcff,
    0x00feff, 0x00fcff, 0xf0ffff, 0xf0ffff, 0x00ffff, 0x80ffff, 0x00ffff, 0x00fcff,
    0x00f8ff, 0x00feff, 0xf0ffff, 0x80ffff, 0x00ffff, 0x00fcff, 0x00f0ff, 0x00feff,
    0xf0ffff, 0xf0ffff, 0x00feff, 0x00f8ff, 0xc0ffff, 0x80ffff, 0x80ffff, 0xc0ffff,
    0xf8ffff, 0x80ffff, 0x00fcff, 0x00c0ff, 0x00f8ff, 0x00feff, 0x00ffff, 0xf0ffff,
    0x00f8ff, 0x00feff, 0x00feff, 0xe0ffff, 0xc0ffff, 0x80ffff, 0x00ffff, 0xf0ffff,
    0xf0ffff, 0x00f8ff, 0x00fcff, 0x00feff, 0x00ffff, 0x00fcff, 0x00fcff, 0x00ffff,
    0x00fcff, 0x00f8ff, 0x00f0ff, 0x00feff, 0x00fcff, 0x00feff, 0x00ffff, 0x00ffff,
    0x00ffff, 0x00fcff, 0x00f8ff, 0x00feff, 0xe0ffff, 0x80ffff, 0x00ffff, 0x00fcff,
    0x00feff, 0x80ffff, 0xf8ffff, 0x00ffff, 0xf0ffff, 0xf8ffff, 0xe0ffff, 0x00ffff,
    0x00fcff, 0xc0ffff, 0xe0ffff, 0xc0ffff, 0x00feff, 0xf0ffff, 0xe0ffff, 0x00f8ff,
    0xc0ffff, 0xf0ffff, 0x80ffff, 0x00ffff, 0xc0ffff, 0xf8ffff, 0xe0ffff, 0x00feff,
    0x00f8ff, 0x00ffff, 0x00ffff, 0x80ffff, 0x00feff, 0x00ffff, 0xe0ffff, 0xf0ffff,
    0x00feff, 0x00feff, 0x00fcff, 0x00fcff, 0x00f8ff, 0x00feff, 0x00f0ff, 0x00f0ff,
    0x00fcff, 0xf0ffff, 0x80ffff, 0x00feff, 0x00fcff, 0x00f0ff, 0x00feff, 0xc0ffff,
    0x00fcff, 0x00ffff, 0x00feff, 0x00f0ff, 0x00fcff, 0x00feff, 0x00f0ff, 0x00feff,
    0x00fcff, 0x00f8ff, 0xe0ffff, 0x80ffff, 0x00fcff, 0x00f8ff, 0xf8ffff, 0x00feff,
    0x00ffff, 0x00feff, 0x00f8ff, 0xc0ffff, 0x80ffff, 0x00c0ff, 0xf0ffff, 0x00feff,
    0x00f8ff, 0x00f0ff, 0x00f8ff, 0x00fcff, 0x00feff, 0x00feff, 0x00ffff, 0xe0ffff,
    0xf0ffff, 0xe0ffff, 0xc0ffff, 0x00feff, 0x80ffff, 0xf0ffff, 0x00ffff, 0x00fcff,
    0x00fcff, 0x00feff, 0xc0ffff, 0x00ffff, 0x80ffff, 0xf0ffff, 0x00f8ff, 0x00ffff,
    0x00fcff, 0x00f0ff, 0x00fcff, 0x00ffff, 0xc0ffff, 0x80ffff, 0x00fcff, 0x00f8ff,
    0x00ffff, 0xc0ffff, 0x00ffff, 0x00e0ff, 0x00feff, 0xf0ffff, 0xe0ffff, 0x00fcff,
    0x00ffff, 0x00f8ff, 0x80ffff, 0xc0ffff, 0x00fcff, 0x00fcff, 0x00ffff, 0xc0ffff,
    0x00fcff, 0x00f0ff, 0x00f8ff, 0xf0ffff, 0xc0ffff, 0x00fcff, 0x00f8ff, 0x80ffff,
    0x00fcff, 0x00f8ff, 0x00e0ff, 0x00feff, 0x80ffff, 0x80ffff, 0xe0ffff, 0x00ffff,
    0x80ffff, 0xf0ffff, 0xf0ffff, 0x00f0ff, 0x00f8ff, 0xf0ffff, 0x00ffff, 0x00feff,
    0x00f0ff, 0x00f0ff, 0xf0ffff, 0x00ffff, 0x00feff, 0x00fcff, 0x00f8ff, 0x00feff,
    0x80ffff, 0x00feff, 0x00fcff, 0x80ffff, 0x00fcff, 0x00ffff, 0x00ffff, 0xc0ffff,
    0x00feff, 0x00feff, 0x00fcff, 0xc0ffff, 0x80ffff, 0x00ffff, 0xf0ffff, 0xc0ffff,
    0x00ffff, 0xc0ffff, 0x00feff, 0x80ffff, 0x00ffff, 0x00fcff, 0x00f8ff, 0x00f8ff,
    0xf8ffff, 0xf8ffff, 0x00f8ff, 0x00feff, 0x00f8ff, 0x80ffff, 0x00ffff, 0x00ffff,
    0x00f8ff, 0x00fcff, 0x00feff, 0x00ffff, 0x00f8ff, 0x00fcff, 0x00f0ff, 0x80ffff,
    0xc0ffff, 0x00ffff, 0xc0ffff, 0x80ffff, 0x00ffff, 0x00feff, 0xc0ffff, 0xc0ffff,
    0x00f0ff, 0x80ffff, 0x80ffff, 0xc0ffff, 0x00e0ff, 0x00feff, 0x00ffff, 0x00f8ff,
    0x00f0ff, 0x00ffff, 0x00ffff, 0xc0ffff, 0x00feff, 0x80ffff, 0xe0ffff, 0xc0ffff,
    0x00f8ff, 0x80ffff, 0x00ffff, 0x00ffff, 0x00ffff, 0x00ffff, 0x00ffff, 0x00ffff,
    0x00ffff, 0x00f0ff, 0x00f8ff, 0x00fcff, 0x00feff, 0x00feff, 0x00ffff, 0x00feff,
    0x00f0ff, 0x00e0ff, 0x00ffff, 0x80ffff, 0x00feff, 0x00fcff, 0x00fcff, 0x00f0ff,
    0x00ffff, 0xc0ffff, 0x00ffff, 0x00feff, 0x00fcff, 0x00fcff, 0x00feff, 0x00ffff,
    0x00fcff, 0xf8ffff, 0xf0ffff, 0x80ffff, 0x00e0ff, 0x80ffff, 0x00ffff, 0x00f8ff,
    0xe0ffff, 0xe0ffff, 0xe0ffff, 0x00f8ff, 0x00f0ff, 0xc0ffff, 0x00fcff, 0x80ffff,
    0xfcffff, 0xfcffff, 0x00ffff, 0x00feff, 0x00feff, 0xe0ffff, 0x00feff, 0xe0ffff,
    0x00ffff, 0xc0ffff, 0xe0ffff, 0xe0ffff, 0xe0ffff, 0x80ffff, 0x00f0ff, 0xe0ffff,
    0x00ffff, 0xf0ffff, 0xf0ffff, 0x00ffff, 0x80ffff, 0x00ffff, 0x00f8ff, 0x00fcff,
    0x00ffff, 0x00e0ff, 0x00f0ff, 0x00f8ff, 0x00ffff, 0xe0ffff, 0x00feff, 0x00f8ff,
    0x80ffff, 0x00ffff, 0xe0ffff, 0x00f8ff, 0x00ffff, 0x00c0ff, 0x00f8ff, 0xfcffff,
    0x00feff, 0xfcffff, 0xf0ffff, 0x00fcff, 0x00e0ff, 0x00f8ff, 0x00feff, 0x00ffff,
    0x00fcff, 0xe0ffff, 0x00f8ff, 0x00c0ff, 0xffffff, 0xffffff, 0xffffff, 0xffffff,
    0xffffff, 0xffffff, 0xfcffff, 0xe0ffff, 0xfcffff, 0xe0ffff, 0xf0ffff, 0xffffff,
    0xffffff, 0xfeffff, 0xffffff, 0xffffff, 0xf8ffff, 0xf0ffff, 0xc0ffff, 0xf8ffff,
    0xfeffff, 0xffffff, 0xfcffff, 0xfcffff, 0xffffff, 0xfeffff, 0xfcffff, 0xffffff,
    0xfeffff, 0xfeffff, 0xfcffff, 0xf8ffff, 0xfeffff, 0xf8ffff, 0xc0ffff, 0xf8ffff,
    0xf0ffff, 0xfcffff, 0xf0ffff, 0xe0ffff, 0xf0ffff, 0xf0ffff, 0xfcffff, 0xfcffff,
    0xf0ffff, 0xe0ffff, 0xf8ffff, 0xf0ffff, 0xf0ffff, 0xfcffff, 0xf0ffff, 0xfcffff,
    0xfcffff, 0xfcffff, 0xf0ffff, 0xe0ffff, 0xfcffff, 0xfcffff, 0xfcffff, 0xfcffff,
    0xe0ffff, 0xe0ffff, 0xfcffff, 0x00f0ff, 0x00f8ff, 0x00feff, 0xf8ffff, 0xf8ffff,
    0xe0ffff, 0xf8ffff, 0xffffff, 0xf0ffff, 0xfcffff, 0xf0ffff, 0xf8ffff, 0xfcffff,
    0xf0ffff, 0xf8ffff, 0xf0ffff, 0xf0ffff, 0xe0ffff, 0xf8ffff, 0xf0ffff, 0xfcffff,
    0xf8ffff, 0xe0ffff, 0xe0ffff, 0xe0ffff, 0xf8ffff, 0xf0ffff, 0xf0ffff, 0xf0ffff,
    0xf0ffff, 0xf0ffff, 0xfcffff, 0xe0ffff, 0xf0ffff, 0xf0ffff, 0xe0ffff, 0xe0ffff,
    0xe0ffff, 0xf0ffff, 0xf0ffff, 0xf0ffff, 0xe0ffff, 0xf0ffff, 0xf0ffff, 0xffffff,
    0xf0ffff, 0xf0ffff, 0xf0ffff, 0xe0ffff, 0xe0ffff, 0xf8ffff, 0xf8ffff, 0xe0ffff,
    0xf0ffff, 0xe0ffff, 0xf0ffff, 0xf0ffff, 0x00f0ff, 0xffffff, 0xf0ffff, 0xf0ffff,
    0xf0ffff, 0xf0ffff, 0xf8ffff, 0xc0ffff, 0xe0ffff, 0xe0ffff, 0xe0ffff, 0xfcffff,
    0xfcffff, 0xc0ffff, 0xe0ffff, 0xe0ffff, 0xf0ffff, 0xf8ffff, 0xfcffff, 0xe0ffff,
    0x00ffff, 0xe0ffff, 0xf8ffff, 0xe0ffff, 0xf0ffff, 0xf0ffff, 0xf0ffff, 0xf0ffff,
    0xe0ffff, 0xf0ffff, 0xe0ffff, 0xfcffff, 0xe0ffff, 0xfcffff, 0xf8ffff, 0xfcffff,
    0xfcffff, 0xe0ffff, 0xe0ffff, 0xe0ffff, 0xe0ffff, 0xe0ffff, 0xf8ffff, 0xe0ffff,
    0xf0ffff, 0xffffff, 0xc0ffff, 0xe0ffff, 0xc0ffff, 0xf8ffff, 0xffffff, 0xe0ffff,
    0xe0ffff, 0xf0ffff, 0xffffff, 0xe0ffff, 0xe0ffff, 0xc0ffff, 0xf8ffff, 0xf0ffff,
    0xe0ffff, 0xf0ffff, 0xf0ffff, 0xc0ffff, 0xf0ffff, 0xe0ffff, 0xf8ffff, 0xc0ffff,
    0x80ffff, 0xf0ffff, 0xfcffff, 0xe0ffff, 0xe0ffff, 0xf0ffff, 0xf0ffff, 0xf0ffff,
    0xf0ffff, 0xe0ffff, 0xe0ffff, 0xe0ffff, 0x00feff, 0xe0ffff, 0xf0ffff, 0x80ffff,
    0x80ffff, 0xc0ffff, 0xc0ffff, 0x00ffff, 0x00ffff, 0xe0ffff, 0x00ffff, 0x00feff,
    0x00fcff, 0x00f0ff, 0x00ffff, 0x00feff, 0xe0ffff, 0x00fcff, 0x00feff, 0x00ffff,
    0xc0ffff, 0xe0ffff, 0x00feff, 0xc0ffff, 0xc0ffff, 0xe0ffff, 0xf0ffff, 0x00f8ff,
    0x00f0ff, 0x00f8ff, 0x00f8ff, 0x00f0ff, 0x00f8ff, 0x00e0ff, 0x00f8ff, 0x00e0ff,
    0x00fcff, 0x00fcff, 0x00feff, 0xe0ffff, 0x00f0ff, 0x00f8ff, 0x00ffff, 0x00ffff,
    0x00ffff, 0x00e0ff, 0x00f8ff, 0x00f0ff, 0x00feff, 0x00fcff, 0xc0ffff, 0x00fcff,
    0x80ffff, 0x00feff, 0x00e0ff, 0x00f0ff, 0xc0ffff, 0x80ffff, 0xc0ffff, 0x00ffff,
    0x00feff, 0x00fcff, 0x00ffff, 0x00f8ff, 0x00fcff, 0x80ffff, 0xc0ffff, 0x00ffff,
    0x00feff, 0x00feff, 0x00ffff, 0x00feff, 0xe0ffff, 0x00feff, 0x00fcff, 0x00f8ff,
    0x00fcff, 0x00feff, 0x00ffff, 0x80ffff, 0xc0ffff, 0xf0ffff, 0xe0ffff, 0x00f8ff,
    0x00f0ff, 0x00f0ff, 0x00f0ff, 0x00e0ff, 0x00e0ff, 0x00ffff, 0x80ffff, 0x00f0ff,
    0x00fcff, 0x00f8ff, 0x00f0ff, 0x00e0ff, 0x00f8ff, 0x00feff, 0x00f8ff, 0x00f0ff,
    0x00e0ff, 0x00c0ff
};
#endif

#endif // _LOCAL_H

#include "shadowd.h"
#include <netinet/in.h>
#include <errno.h>

#ifndef EAGAIN
#define EAGAIN EWOULDBLOCK
#endif

#ifndef EWOULDBLOCK
#define EWOULDBLOCK EAGAIN
#endif

ev_timer _local_timer;
int _launchd_mode;

struct {
    char *remote_host[1];
    char *remote_port;
    char *password;
    char *crypto_method;
    int method;
    int timeout;
} _local_config;

struct listen_ctx *_local_ctx_array;
int _local_ctx_array_len;
struct listen_ctx *_pac_ctx_array;
int _pac_ctx_array_len;
struct listen_ctx _local_ctx;
struct listen_ctx _pac_ctx;

int set_proxy(ProxyStatus status)
{
    NSAutoreleasePool* pool = [[NSAutoreleasePool alloc] init];
    BOOL isEnabled;
    BOOL socks;
    BOOL ret;
    isEnabled = socks = NO;
    switch (status) {
        case kProxyPac:
            isEnabled = YES;
            break;
        case kProxySocks:
            isEnabled = socks = YES;
            break;
        default:
            break;
    }
    NSMutableDictionary *proxySet = [NSMutableDictionary dictionary];
    if (isEnabled) {
        if (socks) {
            NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREF_FILE];
            NSString *excepts = [dict objectForKey:@"EXCEPTION_LIST"];
            if (excepts) {
                NSMutableArray *exceptArray = [NSMutableArray array];
                NSArray *origArray = [excepts componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@", "]];
                for (NSString *s in origArray)
                    if (![s isEqualToString:@""])
                        [exceptArray addObject:s];
                if ([exceptArray count] > 0)
                    [proxySet setObject:exceptArray forKey:@"ExceptionsList"];
            }
            [proxySet setObject:[NSNumber numberWithInt:1] forKey:@"SOCKSEnable"];
            [proxySet setObject:@"127.0.0.1" forKey:@"SOCKSProxy"];
            [proxySet setObject:[NSNumber numberWithInt:LOCAL_PORT] forKey:@"SOCKSPort"];
        }
        else {
            [proxySet setObject:[NSNumber numberWithInt:0] forKey:@"HTTPEnable"];
            [proxySet setObject:[NSNumber numberWithInt:2] forKey:@"HTTPProxyType"];
            [proxySet setObject:[NSNumber numberWithInt:0] forKey:@"HTTPSEnable"];
            [proxySet setObject:[NSNumber numberWithInt:1] forKey:@"ProxyAutoConfigEnable"];
            [proxySet setObject:[NSString stringWithFormat:@"http://127.0.0.1:%d/shadow.pac", PAC_PORT] forKey:@"ProxyAutoConfigURLString"];
        }
    }
    else {
        [proxySet setObject:[NSNumber numberWithInt:0] forKey:@"HTTPEnable"];
        [proxySet setObject:[NSNumber numberWithInt:0] forKey:@"HTTPProxyType"];
        [proxySet setObject:[NSNumber numberWithInt:0] forKey:@"HTTPSEnable"];
        [proxySet setObject:[NSNumber numberWithInt:0] forKey:@"ProxyAutoConfigEnable"];
    }
    ret = YES;
    SCPreferencesRef pref = SCPreferencesCreate(0, CFSTR("shadow"), 0);
    NSDictionary *servicesDict = [NSDictionary dictionaryWithDictionary:(NSDictionary *) SCPreferencesGetValue(pref, CFSTR("NetworkServices"))];
    for (NSString *key in [servicesDict allKeys]) {
        NSDictionary *dict = [servicesDict objectForKey:key];
        NSString *rank = [dict objectForKey:@"PrimaryRank"];
        if (![rank isEqualToString:@"Never"]) {
            NSString *path = [NSString stringWithFormat:@"/NetworkServices/%@/Proxies", key];
            ret &= SCPreferencesPathSetValue(pref, (CFStringRef) path, (CFDictionaryRef) proxySet);
        }
    }
    ret &= SCPreferencesCommitChanges(pref);
    ret &= SCPreferencesApplyChanges(pref);
    SCPreferencesSynchronize(pref);
    SCDynamicStoreRef store = SCDynamicStoreCreate(0, CFSTR("shadow"), 0, 0);
    CFRelease(store);
    CFRelease(pref);
    [pool release];
    return ret;
}

static void listen_timeout_cb(EV_P_ ev_timer *watcher, int revents)
{
    LOGD("Service timeout, exit");
    ev_break(EV_A_ EVBREAK_ALL);
}

int get_pac_file_path(char *buf)
{
    NSAutoreleasePool* pool = [[NSAutoreleasePool alloc] init];
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREF_FILE];
    int result = 1;
    if (dict && [[dict objectForKey:@"AUTO_PROXY"] boolValue]) {
        NSString *filePath = [(NSString *) [dict objectForKey:@"PAC_FILE"] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        int len = [filePath length];
        if (filePath && len > 0) {
            strncpy(buf, [filePath cStringUsingEncoding:NSUTF8StringEncoding], BUFF_MAX);
            buf[BUFF_MAX - 1] = 0;
            result = 0;
        }
    }
    [pool release];
    return result;
}

void send_pac_exception(FILE *stream)
{
    NSAutoreleasePool* pool = [[NSAutoreleasePool alloc] init];
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:PREF_FILE];
    NSString *excepts = [dict objectForKey:@"EXCEPTION_LIST"];
    if (excepts) {
        NSArray *origArray = [excepts componentsSeparatedByCharactersInSet:[NSCharacterSet characterSetWithCharactersInString:@"\\', "]];
        BOOL first = YES;
        for (NSString *str in origArray)
            if (![str isEqualToString:@""]) {
                if (first) {
                    fprintf(stream, PAC_EXCEPT_HEAD);
                    first = NO;
                    fprintf(stream, "'%s'", [str cStringUsingEncoding:NSUTF8StringEncoding]);
                }
                else {
                    fprintf(stream, ", '%s'", [str cStringUsingEncoding:NSUTF8StringEncoding]);
                }
            }
        if (first == NO) {
            fprintf(stream, PAC_EXCEPT_TAIL);
        }
    }
    [pool release];
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

static void pac_recv_cb (EV_P_ ev_io *w, int revents)
{
    char will_update;
    char will_set_proxy;
    char use_pac;
    char exception_sent;
    char found_pac_func;
    int len;
    FILE *stream;
    FILE *pacfile;
    char *buf;
    char *now_buf;
    char *pac_func_name;
    char *pac_except_start;
    const char *set_proxy_header;
    int sent_num;
    ProxyStatus set_proxy_status;
    struct pac_server_ctx *pac;

    will_update = 0;
    will_set_proxy = 0;
    set_proxy_status = kProxyNone;
    pac = (struct pac_server_ctx *) w;
    
    if (pac == NULL) {
        LOGE("pac ctx is null");
        return;
    }
    else if (pac->buf == NULL) {
        LOGE("buffer of pac ctx is null");
        return;
    }

    buf = pac->buf;
    buf[0] = 0;
    len = recv(pac->fd, buf, BUFF_MAX - 1, 0);
    if (len == 0) {
        close_and_free_pac(EV_A_ pac);
        return;
    }
    else if (len < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            ERROR("pac recv");
            close_and_free_pac(EV_A_ pac);
        }
        return;
    }
    else  {
        buf[len] = '\0';
        if (strstr(buf, UPDATE_CONF)) {
            will_update = 1;
        } else if (strstr(buf, SET_PROXY_NONE)) {
            set_proxy_header = SET_PROXY_NONE;
            set_proxy_status = kProxyNone;
            will_set_proxy = 1;
        } else if (strstr(buf, SET_PROXY_SOCKS)) {
            set_proxy_header = SET_PROXY_SOCKS;
            set_proxy_status = kProxySocks;
            will_set_proxy = 1;
        } else if (strstr(buf, SET_PROXY_PAC)) {
            set_proxy_header = SET_PROXY_PAC;
            set_proxy_status = kProxyPac;
            will_set_proxy = 1;
        }
    }

    if (!(stream = fdopen(pac->fd, "w"))) {
        ERROR("fdopen");
        return;
    }

    fprintf(stream, HTTP_RESPONSE);

    if (will_update) {
        LOGD("Updating server settings...");
        update_config();
        if (_launchd_mode) {
            update_ctx_array_conf(_local_ctx_array, _local_ctx_array_len);
        } else {
            update_ctx_conf(&_local_ctx);
        }
        fprintf(stream, "Updated.\n");
    }
    else if (will_set_proxy) {
        if (set_proxy(set_proxy_status)) {
            fprintf(stream, "Updated.\n");
            LOGD("Proxy setting updated: %s", set_proxy_header);
        } else {
            fprintf(stream, "Failed.\n");
            LOGE("Failed to update proxy: %s", set_proxy_header);
        }
    }
    else {
        use_pac = 0;
        if (!get_pac_file_path(buf)) {
            if ((pacfile = fopen(buf, "r")) != NULL) {
                use_pac = 1;
                exception_sent = 0;
                found_pac_func = 0;
                while ((len = fread(buf, 1, BUFF_MAX - 1, pacfile)) > 0) {
                    buf[len] = 0;
                    now_buf = buf;
                    if (!exception_sent) {
                        pac_func_name = strstr(buf, PAC_FUNC);
                        if (pac_func_name || found_pac_func) {
                            if (pac_func_name)
                                found_pac_func = 1;
                            else
                                pac_func_name = buf;
                            pac_except_start = strchr(pac_func_name, '{');
                            if (pac_except_start) {
                                sent_num = (pac_except_start - buf) + 1;
                                fwrite(buf, 1, sent_num, stream);
                                send_pac_exception(stream);
                                exception_sent = 1;
                                now_buf += sent_num;
                                len -= sent_num;
                            }
                        }
                    }
                    if (len > 0)
                        fwrite(now_buf, 1, len, stream);
                }
                fclose(pacfile);
            }
        }
        if (!use_pac) {
            fprintf(stream, EMPTY_PAC_HEAD);
            send_pac_exception(stream);
            fprintf(stream, EMPTY_PAC_TAIL, LOCAL_PORT);
        }
    }
    fflush(stream);
    fclose(stream);
    close_and_free_pac(EV_A_ pac);
}

static void pac_accept_cb (EV_P_ ev_io *w, int revents)
{
    struct listen_ctx *listener = (struct listen_ctx *) w;
    int serverfd;
    socklen_t socksize;
    struct sockaddr_in client;
    struct pac_server_ctx *pac;

    memset(&client, 0, sizeof(client));
    socksize = sizeof(struct sockaddr_in);
    serverfd = accept(listener->fd, (struct sockaddr *) &client, &socksize);
    if (serverfd < 0) {
        ERROR("accept");
        return;
    }
    ev_timer_again(EV_A_ &_local_timer);
    setnonblocking(serverfd);
    pac = (struct pac_server_ctx *) malloc(sizeof(struct pac_server_ctx));
    pac->buf = (char *) malloc(BUFF_MAX);
    pac->fd = serverfd;
    ev_io_init(&pac->io, pac_recv_cb, serverfd, EV_READ);  
    ev_io_start(EV_A_ &pac->io);
}

int store_config(char **config_ptr, const char *new_config, const char *default_value)
{
    int changed = 0;
    if (!*config_ptr) {
        if (new_config) {
            *config_ptr = strdup(new_config);
        } else {
            *config_ptr = strdup(default_value);
        }
        changed = 1;
    } else if (new_config) {
        if (strcmp(*config_ptr, new_config)) {
            free(*config_ptr);
            *config_ptr = strdup(new_config);
            changed = 1;
        }
    }
    return changed;
}

void update_config()
{
    NSAutoreleasePool* pool = [[NSAutoreleasePool alloc] init];
    NSDictionary *prefDict = [NSDictionary dictionaryWithContentsOfFile:PREF_FILE];
    NSString *remoteServer = [prefDict objectForKey:@"REMOTE_SERVER"];
    NSString *remotePort = [prefDict objectForKey:@"REMOTE_PORT"];
    NSString *socksPass = [prefDict objectForKey:@"SOCKS_PASS"];
    NSString *cryptoMethod = [prefDict objectForKey:@"CRYPTO_METHOD"];
    store_config(&_local_config.remote_host[0], [remoteServer cStringUsingEncoding:NSUTF8StringEncoding], "127.0.0.1");
    store_config(&_local_config.remote_port, [remotePort cStringUsingEncoding:NSUTF8StringEncoding], "8080");
    store_config(&_local_config.password, [socksPass cStringUsingEncoding:NSUTF8StringEncoding], "123456");
    int key_changed = store_config(&_local_config.crypto_method, [cryptoMethod cStringUsingEncoding:NSUTF8StringEncoding], "table");
    LOGD("Plist config: %s", [PREF_FILE cStringUsingEncoding:NSUTF8StringEncoding]);
    if (![[NSFileManager defaultManager] fileExistsAtPath:PREF_FILE]){
        LOGE("Plist config file not found, use default");
    }
    LOGD("Remote server: %s:%s", _local_config.remote_host[0], _local_config.remote_port);
    if (key_changed) {
        _local_config.method = enc_init(_local_config.password, _local_config.crypto_method);
        LOGD("Crypto cipher: %s", _local_config.crypto_method);
    }
    [pool release];
}

void update_ctx_conf(struct listen_ctx *ctx)
{
    ctx->remote_num = 1;
    ctx->remote_host = _local_config.remote_host;
    ctx->remote_port = _local_config.remote_port;
    ctx->timeout = _local_config.timeout;
    ctx->iface = NULL;
    ctx->method = _local_config.method;
}

void update_ctx_array_conf(struct listen_ctx *ctx_array, int array_len)
{
    int i;
    for (i = 0; i < array_len; i++) {
        update_ctx_conf(&ctx_array[i]);
    }
}

struct listen_ctx *listen_from_launchd(EV_P_ int *array_len, const char *socket_name, launch_data_t sockets_dict, ev_handler handler)
{
    launch_data_t listening_fd_array;
    launch_data_t this_listening_fd;
    int i;
    listening_fd_array = launch_data_dict_lookup(sockets_dict, socket_name);
    if (NULL == listening_fd_array) {
        LOGE("no %s entry found in plist", socket_name);
        return NULL;
    }
    *array_len = launch_data_array_get_count(listening_fd_array);
    if (*array_len <= 0) {
        LOGE("no fd found from launchd");
        return NULL;
    }
    struct listen_ctx *ctx_array = (struct listen_ctx *) malloc(sizeof(struct listen_ctx) * (*array_len));
    int found_legal_fd = 0;
    for (i = 0; i < *array_len; i++) {
        this_listening_fd = launch_data_array_get_index(listening_fd_array, i);
        ctx_array[i].fd = launch_data_get_fd(this_listening_fd);
        update_ctx_conf(&ctx_array[i]);
        if (ctx_array[i].fd >= 0) {
            ev_io_init(&ctx_array[i].io, handler, ctx_array[i].fd, EV_READ);
            ev_io_start(EV_A_ &ctx_array[i].io);
            if (!found_legal_fd)
                found_legal_fd = 1;
        }
    }
    if (!found_legal_fd) {
        free(ctx_array);
        LOGE("no legal fd found from launchd");
        return NULL;
    }
    return ctx_array;
}

int listen_from_port(EV_P_ struct listen_ctx *ctx, int port, ev_handler handler)
{
    int listenfd;
    char buf[30];
    sprintf(buf, "%d", port);
    listenfd = create_and_bind(buf);
    if (listenfd < 0) {
        LOGE("bind error");
        return 1;
    }
    if (listen(listenfd, SOMAXCONN) == -1) {
        LOGE("listen error");
        return 1;
    }
    setnonblocking(listenfd);
    ctx->fd = listenfd;
    update_ctx_conf(ctx);
    ev_io_init(&ctx->io, handler, ctx->fd, EV_READ);
    ev_io_start(EV_A_ &ctx->io);
    return 0;
}

int main (int argc, const char *argv[])
{
    int timeout = 0;
    int local_timeout = 0;
    int i;

    _launchd_mode = 0;
    _local_config.remote_host[0] = NULL;
    _local_config.remote_port = NULL;
    _local_config.password = NULL;
    _local_config.crypto_method = NULL;
    _local_config.method = TABLE;
    _local_config.timeout = REMOTE_TIMEOUT;

    if (argc > 1) {
        for (i = 1; i < argc; i++) {
            if (strcmp(argv[i], "-d") == 0)
                _launchd_mode = 1;
            else if (isdigit(argv[i][0])) {
                if (!timeout)
                    timeout = atoi(argv[i]);
                else if (!local_timeout)
                    local_timeout = atoi(argv[i]);
            }
        }
    }
    if (timeout <= 0)
        timeout = REMOTE_TIMEOUT;
    if (local_timeout <= 0)
        local_timeout = LOCAL_TIMEOUT;
    _local_config.timeout = timeout;

    LOGD("ShadowSocks (libev) for Darwin v%s", VERSION);
    update_config();
    LOGD("Exit no action: %ds", local_timeout);
    LOGD("Remote timeout: %ds", timeout);
    struct ev_loop *loop = ev_default_loop(0);
    if (!loop) {
        FATAL("ev_loop error");
    }
    signal(SIGPIPE, SIG_IGN);
    LOGD("Socks server: 127.0.0.1:%d", LOCAL_PORT);
    LOGD("Pac httpd: 127.0.0.1:%d", PAC_PORT);
    if (_launchd_mode) {
        launch_data_t sockets_dict;
        launch_data_t checkin_response;
        launch_data_t checkin_request;
        int listen_ok;
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
            if ((_local_ctx_array = listen_from_launchd(EV_A_ &_local_ctx_array_len, LAUNCHD_NAME_SOCKS, sockets_dict, accept_cb)) == NULL)
                break;
            if ((_pac_ctx_array = listen_from_launchd(EV_A_ &_pac_ctx_array_len, LAUNCHD_NAME_PAC, sockets_dict, pac_accept_cb)) == NULL)
                break;
            listen_ok = 1;
        } while (0);
        if (listen_ok >= 0) {
            launch_data_free(checkin_response);
            launch_data_free(checkin_request);
        }
        if (listen_ok != 1)
            return -1;
    }
    else {
        if (listen_from_port(EV_A_ &_local_ctx, LOCAL_PORT, accept_cb)) {
            LOGE("listen on socks port failed");
            return -1;
        }
        if (listen_from_port(EV_A_ &_pac_ctx, PAC_PORT, pac_accept_cb)) {
            LOGE("listen on pac port failed");
            return -1;
        }
    }
    ev_timer_init(&_local_timer, listen_timeout_cb, 0, local_timeout);
    ev_timer_again(EV_A_ &_local_timer);
    LOGD("Service running...");
    ev_run(loop, 0);
    return 0;
}

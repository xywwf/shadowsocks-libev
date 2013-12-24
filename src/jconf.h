#ifndef _JCONF_H
#define _JCONF_H

#define MAX_REMOTE_NUM 10
#define MAX_CONF_SIZE 16 * 1024
#define DNS_THREAD_NUM 4
#define MAX_UDP_CONN_NUM 4096
#define MAX_EXCEPT_NUM 1024

typedef struct
{
    char *host;
    char *port;
} remote_addr_t;

typedef char *except_addr_t;

typedef struct
{
    int  remote_num;
    remote_addr_t remote_addr[MAX_REMOTE_NUM];
    char *remote_port;
    char *local_addr;
    char *local_port;
    char *password;
    char *method;
    char *timeout;
    char *pac_port;
    char *pac_path;
    int except_num;
    except_addr_t except_list[MAX_EXCEPT_NUM];
} jconf_t;

jconf_t *read_jconf(const char* file);
void save_str(char **conf_p, char *value_str);

#endif // _JCONF_H

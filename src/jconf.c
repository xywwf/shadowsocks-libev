#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "jconf.h"
#include "json.h"
#include "string.h"

static char *to_string(const json_value *value)
{
    if (value->type == json_string)
    {
        return ss_strndup(value->u.string.ptr, value->u.string.length);
    }
    else if (value->type == json_integer)
    {
#ifdef __MINGW32__
        return strdup(ss_itoa(value->u.integer));
#else
        return strdup(itoa(value->u.integer));
#endif
    }
    else if (value->type == json_null)
    {
        return "null";
    }
    LOGE("Invalid config format: %d", value->type);
    return NULL;
}

void save_str(char **conf_p, char *value_str)
{
    if (conf_p == NULL) {
        return;
    }
    char *conf_str = *conf_p;
    if (conf_str != NULL) {
        if (conf_str != value_str) {
            free(conf_str);
            *conf_p = value_str;
        }
    } else {
        *conf_p = value_str;
    }
}

static void save_json_value(char **conf_p, const json_value *value)
{
    if (conf_p == NULL) {
        return;
    }
    save_str(conf_p, to_string(value));
}

void free_addr(ss_addr_t *addr)
{
    free(addr->host);
    free(addr->port);
    addr->host = NULL;
    addr->port = NULL;
}

void parse_addr(const char *str, ss_addr_t *addr)
{
    int ret = -1, n = 0;
    char *pch;
    pch = strchr(str, ':');
    while (pch != NULL)
    {
        n++;
        ret = pch - str;
        pch = strchr(pch + 1, ':');
    }
    if (n > 1) {
        if (strcmp(str+ret, "]") != 0)
        {
            ret = -1;
        }
    }
    if (ret == -1)
    {
        save_str((char **) &addr->host, (char *) str);
        addr->port = NULL;
    }
    else
    {
        save_str((char **) &addr->host, ss_strndup(str, ret));
        save_str((char **) &addr->port, (char *) str + ret + 1);
    }
}

static void parse_addr_value(const json_value *value, ss_addr_t *addr)
{
    char *str;
    if (addr == NULL) {
        return;
    }
    str = to_string(value);
    if (str == NULL) {
        return;
    }
    parse_addr(str, addr);
}

jconf_t *read_jconf(const char* file)
{

    static jconf_t conf;

    char *buf;
    json_value *obj;

    FILE *f = fopen(file, "r");
    if (f == NULL) FATAL("Invalid config path.");

    fseek(f, 0, SEEK_END);
    long pos = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (pos >= MAX_CONF_SIZE) FATAL("Too large config file.");

    buf = malloc(pos + 1);
    if (buf == NULL) FATAL("No enough memory.");

    int nread = fread(buf, pos, 1, f);
    if (!nread) FATAL("Failed to read the config file.");
    fclose(f);

    buf[pos] = '\0'; // end of string

    json_settings settings = { 0 };
    char error_buf[512];
    obj = json_parse_ex(&settings, buf, pos, error_buf);

    if (obj == NULL)
    {
        LOGE("JSON parse error: %s", error_buf);
        FATAL("config parse failed.");
    }

    if (obj->type == json_object)
    {
        int i, j;

        conf.except_num = 0;
        save_str(&conf.pac_path, NULL);

        for (i = 0; i < obj->u.object.length; i++)
        {
            char *name = obj->u.object.values[i].name;
            json_value *value = obj->u.object.values[i].value;
            if (strcmp(name, "server") == 0)
            {
                if (value->type == json_array)
                {
                    for (j = 0; j < value->u.array.length; j++)
                    {
                        if (j >= MAX_REMOTE_NUM) break;
                        json_value *v = value->u.array.values[j];
                        parse_addr_value(v, conf.remote_addr + j);
                        conf.remote_num = j + 1;
                    }
                }
                else if (value->type == json_string)
                {
                    save_json_value((char **) &conf.remote_addr[0].host, value);
                    conf.remote_addr[0].port = NULL;
                    conf.remote_num = 1;
                }
            }
            else if (strcmp(name, "except_list") == 0)
            {
                if (value->type == json_array)
                {
                    for (j = 0; j < value->u.array.length; j++)
                    {
                        if (j >= MAX_EXCEPT_NUM) break;
                        json_value *v = value->u.array.values[j];
                        save_json_value(&conf.except_list[j], v);
                        conf.except_num = j + 1;
                    }
                }
                else if (value->type == json_string)
                {
                    save_json_value(&conf.except_list[0], value);
                    conf.except_num = 1;
                }
            }
            else if (strcmp(name, "server_port") == 0)
            {
                save_json_value(&conf.remote_port, value);
            }
            else if (strcmp(name, "local") == 0)
            {
                save_json_value(&conf.local_addr, value);
            }
            else if (strcmp(name, "local_port") == 0)
            {
                save_json_value(&conf.local_port, value);
            }
            else if (strcmp(name, "password") == 0)
            {
                save_json_value(&conf.password, value);
            }
            else if (strcmp(name, "method") == 0)
            {
                save_json_value(&conf.method, value);
            }
            else if (strcmp(name, "timeout") == 0)
            {
                save_json_value(&conf.timeout, value);
            }
            else if (strcmp(name, "pac_port") == 0)
            {
                save_json_value(&conf.pac_port, value);
            }
            else if (strcmp(name, "pac_path") == 0)
            {
                save_json_value(&conf.pac_path, value);
            }
        }
    }
    else
    {
        FATAL("Invalid config file");
    }

    free(buf);
    json_value_free(obj);
    return &conf;

}

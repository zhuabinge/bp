#include<stdio.h>
#include<stdlib.h>
#define __USE_GNU
#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>

#include "../spoofer_system/spoofer.h"
#include "../spoofer_pool/spo_pool.h"
#include "spo_linux.h"

extern char **environ;

static char *spo_os_argv_last = NULL;
static char *spo_os_env_last = NULL;
char **sys_argv = NULL;
uint sys_argc = 0;


static SPO_RET_STATUS spo_init_set_proc_title();



/**
 *
 *  bind cpu for the process.
 *
 *  @param cpu_id, is the cpu id.
 *
 *  @param pid, is the proc id.
 *
 *  @return nothing.
 *
 *  status finished, tested.
 *
 **/

void spo_bind_cpu(int cpu_id, pid_t pid)
{
    cpu_set_t mask; /*mask set.*/

    cpu_id = cpu_id % sysconf(_SC_NPROCESSORS_CONF);

    CPU_ZERO(&mask);    /*clear mask*/
    CPU_SET(cpu_id, &mask); /*bind cpu*/

    if (sched_setaffinity(pid, sizeof(mask), &mask) == -1) {
#if SPO_DEBUG
        printf("bind cpu err\n");
#endif
    }
}


char *spo_strtok(char *str, const char *delim)
{
    static char *p = NULL;
    static char *start = NULL;
    size_t i = 0;
    size_t len = 0;
    size_t del_len = 0;

    if (str != NULL) start = p = str;

    start = p;
    len = strlen(p);

    if (delim == NULL) return p;
    del_len = strlen(delim);

    for (i = 0; i < len; i++) {
        if (memcmp(p, delim, del_len) == 0) {
            *p = '\0';
            p += del_len;
            return start;
        }
        p++;
    }

    return start;
}


u_char *spo_cpystrn(u_char *dst, u_char *src, size_t n)
{
    if (n == 0) return dst;

    while (--n) {
        *dst = *src;

        if (*dst == '\0') {
            return dst;
        }

        dst++;
        src++;
    }

    *dst = '\0';

    return dst;
}


static SPO_RET_STATUS spo_init_set_proc_title()
{
    char *p = NULL;
    size_t size = 0;
    uint i = 0;

    for (i = 0; environ[i]; i++) {
        size += strlen(environ[i]) + 1;
    }

    if ((p = spo_calloc(size)) == NULL) return SPO_FAILURE;

    spo_os_argv_last = sys_argv[0];

    for (i = 0; sys_argv[i]; i++) {
        if (spo_os_argv_last == sys_argv[i]) {
            spo_os_argv_last = sys_argv[i] + strlen(sys_argv[i]) + 1;
        }
    }

    spo_os_env_last = spo_os_argv_last;

    for (i = 0; environ[i]; i++) {
        if (spo_os_env_last == environ[i]) {
            size = strlen(environ[i]) + 1;
            spo_os_env_last = environ[i] + size;
            strncpy(p, environ[i], size);
            environ[i] = (char *) p;
            p += size;
        }
    }

    spo_os_argv_last--;

    return SPO_OK;
}


SPO_RET_STATUS spo_set_proc_titel(char *title)
{
    u_char *p = NULL;
    u_char *q = NULL;
    uint i = 0;
    size_t size = 0;
    u_char *b = NULL;
    char buf[512] = {'\0'};

    spo_init_set_proc_title();

    if (sys_argc >= 2) {
        size = spo_os_argv_last - sys_argv[1] + 1;
        memcpy(buf, sys_argv[1], size);
    }

    p = spo_cpystrn((u_char *) sys_argv[0], (u_char *) "spoofer:", spo_os_env_last - sys_argv[0]);
    p = spo_cpystrn(p, (u_char *) title, spo_os_env_last - (char *) p);

    if (sys_argc >= 2) {
        b = (u_char *) buf;
        q = p;

        for (i = 1; i < sys_argc; i++) {
            q = p;
            p = spo_cpystrn(p, b, size);
            p++;
            b += (p - q);
            sys_argv[i] = (char *) q;
        }

        sys_argv[sys_argc] = (char *) p;
    }

    memset(p, '\0', spo_os_env_last - (char *) p);

    return SPO_OK;
}

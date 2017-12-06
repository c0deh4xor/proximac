//  local.c
//  proximac
//
//  Created by jedihy on 15-5-12.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <sys/kern_control.h>
#include <sys/sys_domain.h>

#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <uv.h>
#include <unistd.h>
#include <getopt.h>
#include "jconf.h"
#include "local.h"
#include "utils.h"
#include "socks5.h"

conf_t conf;
FILE* logfile = NULL;
uv_loop_t* loop = NULL;
int log_to_file = 0;
int gSocket = -1;
int gSocket_for_release = -1;

#define MYBUNDLEID "com.proximac.kext"

extern struct proxy_server sock_proxy;
extern struct proxy_server http_proxy;

// pid rb-tree structure
/* Red-black tree of pid to be Hooked for proximac */
struct pid_tree pid_list;

static inline int pid_cmp(const struct pid* tree_a, const struct pid* tree_b)
{
    if (tree_a->pid == tree_b->pid) {
        return 0;
    }
    return tree_a->pid < tree_b->pid ? -1 : 1;
}

RB_GENERATE(pid_tree, pid, rb_link, pid_cmp);

void final_after_close_cb(uv_handle_t* handle)
{
    server_ctx_t* server_ctx = handle->data;
    
    LOGI("final_after_close_cb : %s", server_ctx->remote_addr);
    
    if (server_ctx->buf != NULL) {
        free(server_ctx->buf);
    }
    free(server_ctx);
}

void server_after_close_cb(uv_handle_t* handle)
{
    server_ctx_t* server_ctx = handle->data;
    uv_read_stop((uv_stream_t*)&server_ctx->remote_handle);
    uv_close((uv_handle_t*)(void*)&server_ctx->remote_handle, final_after_close_cb);
}

void remote_after_close_cb(uv_handle_t* handle)
{
    server_ctx_t* server_ctx = handle->data;
    uv_read_stop((uv_stream_t*)&server_ctx->server_handle);
    uv_close((uv_handle_t*)(void*)&server_ctx->server_handle, final_after_close_cb);
}

void remote_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf)
{
    *buf = uv_buf_init((char*)malloc(BUF_SIZE), BUF_SIZE);
    assert(buf->base != NULL);
}

struct proxy_server* get_proxy()
{
    switch (conf.type) {
        case SOCK:
            return &sock_proxy;
        case HTTP:
            return &http_proxy;
        default:
            return NULL;
    }
}

void server_accept_cb(uv_stream_t* server, int status)
{
    if (status) {
        LOGE("server accept failed!");
        return;
    }

    server_ctx_t* server_ctx = calloc(1, sizeof(server_ctx_t));
    server_ctx->proxy = get_proxy();
    if(NULL == server_ctx->proxy)
    {
        LOGE("wrong proxy type!");
        return;
    }
    
    // calloc set all members to zero!
    server_ctx->server_handle.data = server_ctx;
    server_ctx->remote_handle.data = server_ctx;
    uv_tcp_init(loop, &server_ctx->server_handle);
    uv_tcp_init(loop, &server_ctx->remote_handle);
    uv_tcp_nodelay(&server_ctx->server_handle, 1);

    int r = uv_accept(server, (uv_stream_t*)&server_ctx->server_handle);
    if (r) {
        LOGE("Fail to accept connection failed: %d", r);
        uv_close((uv_handle_t*)&server_ctx->server_handle, NULL);
        return;
    }
    
    LOGI("server_accept_cb: type=%d", server_ctx->remote_handle.type);
    uv_read_start((uv_stream_t*)&server_ctx->server_handle, server_alloc_cb, server_read_cb);
}

void server_alloc_cb(uv_handle_t* handle, size_t size, uv_buf_t* buf)
{
    *buf = uv_buf_init((char*)malloc(BUF_SIZE), BUF_SIZE);
    assert(buf->base != NULL);
}

void server_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    server_ctx_t* server_ctx = stream->data;
    if (nread <= 0) {
        if (nread == 0) {
            if (buf->len > 0) {
                free(buf->base);
            }
            return;
        }
        TRY_CLOSE(server_ctx, &server_ctx->server_handle, server_after_close_cb);
    } else {
        if (server_ctx->server_stage == 0) {
            uv_read_stop(stream);
            server_ctx->buf = buf->base;
            server_ctx->buf_len = nread;
            server_ctx->addrlen = server_ctx->buf[0];
            
            //get addr
            memcpy(server_ctx->remote_addr, server_ctx->buf + sizeof(char), server_ctx->addrlen);
            memcpy(&server_ctx->port, server_ctx->buf + 1 + server_ctx->addrlen, sizeof(server_ctx->port));
            
            LOGI("remote: addr=%s, port=%d", server_ctx->remote_addr, server_ctx->port);
            // don't allow to connect proxy directly
            if(!strcmp(conf.local_address, server_ctx->remote_addr)) {
                TRY_CLOSE(server_ctx, &server_ctx->server_handle, server_after_close_cb);
                return;
            }
            
            unsigned long tmpbuf_len = nread - server_ctx->addrlen - 1 - sizeof(server_ctx->port);
            if (tmpbuf_len) {
                char* tmpbuf = malloc(tmpbuf_len);
                memcpy(tmpbuf, server_ctx->buf + server_ctx->addrlen + 1 + sizeof(server_ctx->port), tmpbuf_len);

                server_ctx->buf_len = tmpbuf_len;
                server_ctx->buf = tmpbuf;
            } else {
                server_ctx->buf_len = 0;
                server_ctx->buf = NULL;
            }

            free(buf->base);

            // get proxy config
            struct sockaddr_in remote_addr;
            memset(&remote_addr, 0, sizeof(remote_addr));
            uv_ip4_addr(conf.local_address, conf.localport, &remote_addr);

            uv_connect_t* remote_conn_req = calloc(1, sizeof(uv_connect_t));
            remote_conn_req->data = server_ctx;
            LOGI("create proxy: addr=%s, port=%d", conf.local_address, conf.localport);
            
            uv_tcp_connect(remote_conn_req, &server_ctx->remote_handle,
                           (struct sockaddr*)&remote_addr,
                           server_ctx->proxy->connect_to_remote_cb);
        } else if (server_ctx->server_stage == 1) {
            write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));

            wr->req.data = server_ctx;
            wr->buf = uv_buf_init(buf->base, (unsigned int)nread);

            uv_write(&wr->req, (uv_stream_t*)&server_ctx->remote_handle, &wr->buf, 1, server_ctx->proxy->remote_write_cb);
        }
    }
}

int tell_kernel_to_unhook()
{
    errno_t retval = 0;

    int result = 0;
    unsigned int size = sizeof(result);
    retval = getsockopt(gSocket, SYSPROTO_CONTROL, PROXIMAC_OFF, &result, &size);
    if (-1 == retval) {
        LOGI("getsockopt failure PROXIMAC_OFF");
        exit(EXIT_FAILURE);
    } else if (EINPROGRESS == retval) {
        LOGI("ERROR: Maybe Proximac is unregistering filters...");
    }

    if (result == EINPROGRESS) {
        LOGI("Proximac is unregistering filters...");
        LOGI("Wait a few sec to for Proximac to release kernel resources");
    }

    return 0;
}

int tell_kernel_to_hook()
{
    struct ctl_info ctl_info;
    struct sockaddr_ctl sc;
    errno_t retval = 0;

    gSocket = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (gSocket < 0) {
        LOGI("socket() failed.");
        exit(EXIT_FAILURE);
    }

    bzero(&ctl_info, sizeof(struct ctl_info));

    strcpy(ctl_info.ctl_name, MYBUNDLEID);
    if (ioctl(gSocket, CTLIOCGINFO, &ctl_info) == -1) {
        LOGE("ioctl CTLIOCGINFO");
        exit(EXIT_FAILURE);
    }

    bzero(&sc, sizeof(struct sockaddr_ctl));
    sc.sc_len = sizeof(struct sockaddr_ctl);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = SYSPROTO_CONTROL;
    sc.sc_id = ctl_info.ctl_id;
    sc.sc_unit = 0;

    if (connect(gSocket, (struct sockaddr*)&sc, sizeof(struct sockaddr_ctl))) {
        LOGI("Connection to kernel failed. The kernel module may not be correctly loaded.");
        exit(EXIT_FAILURE);
    }

    int vpn_mode = 0;
    if (conf.vpn_mode == 1) {
        vpn_mode = 1;
    }

    // enable proxy
    SET_PARAM(gSocket, PROXIMAC_ON, vpn_mode, "setsockopt failure PROXIMAC_ON");

    // bypass self
    if (vpn_mode == 1) {
        SET_PARAM(gSocket, NOT_TO_HOOK, conf.proxyapp_hash, "setsockopt failure NOT_TO_HOOK");
    }
    
    // bypass proxy server
    char proxy_addr[100] = {0};
    memset(proxy_addr, 0, sizeof(proxy_addr));
    snprintf(proxy_addr, sizeof(proxy_addr), "%s:%d", conf.local_address, conf.localport);
    int proxy_addr_hash = hash_all(proxy_addr);
    LOGI("proxy addr:%s,   hash: %d", proxy_addr, proxy_addr_hash);
    SET_PARAM(gSocket, PROXY_SERVER, proxy_addr_hash, "setsockopt failure PROXY_SERVER");

    // add process to be hooked
    struct pid* pid_tmp = NULL;
    int pidset_checksum = 0;
    RB_FOREACH(pid_tmp, pid_tree, &pid_list)
    {
        SET_PARAM(gSocket, HOOK_PID, pid_tmp->pid, "setsockopt failure HOOK_PID");
        pidset_checksum += pid_tmp->pid;
    }

    // check pid checksum
    int pidget_checksum = 0;
    unsigned int size = sizeof(pidget_checksum);
    GET_PARAM(gSocket, HOOK_PID, pidget_checksum, size, "getsockopt HOOK_PID failure");
    if (pidget_checksum == pidset_checksum) {
        LOGI("Hook Succeed!");
    } else {
        LOGI("Hook Fail! pidget_checksum = %d pidset_checksum = %d", pidget_checksum, pidset_checksum);
    }

    // check pidlist number
    int pid_num = 0;
    size = sizeof(pid_num);
    GET_PARAM(gSocket, PIDLIST_STATUS, pid_num, size, "getsockopt PIDLIST_STATUS failure");
    
    if (conf.vpn_mode == 1) {
        LOGI("All traffic will be redirected to this proxy");
    } else {
        LOGI("The total number of process that will be hooked = %d", pid_num);
    }
    
    return retval;
}

void signal_handler_ctl_z(uv_signal_t* handle, int signum)
{
    LOGI("Terminal signal captured! Exiting and turning off kernel extension...");
    tell_kernel_to_unhook();
    uv_loop_t* loop = handle->data;
    uv_signal_stop(handle);
    uv_stop(loop);
    exit(0);
}

void signal_handler_ctl_c(uv_signal_t* handle, int signum)
{
    LOGI("Ctrl+C pressed, tell kernel to UnHook socket");
    tell_kernel_to_unhook();
    uv_loop_t* loop = handle->data;
    uv_signal_stop(handle);
    uv_stop(loop);
    exit(0);
}

int main(int argc, char** argv)
{
    int c, option_index = 0, daemon = 0;
    char* configfile = NULL;
    char* logfile_path = "./proximac.log";
    RB_INIT(&pid_list);
    opterr = 0;
    static struct option long_options[] = {
        { 0, 0, 0, 0 }
    };

    while ((c = getopt_long(argc, argv, "c:d",
                long_options, &option_index)) != -1) {
        switch (c) {
        case 'd': {
            daemon = 1;
            break;
        }
        case 'c': {
            configfile = optarg;
            break;
        }
        default: {
            opterr = 1;
            break;
        }
        }
    }

    if (opterr == 1 || configfile == NULL) {
        fprintf(stderr, "No config file specified!\n");
        usage();
        exit(EXIT_FAILURE);
    }
    
    if (log_to_file) {
        USE_LOGFILE(logfile_path);
    }

    if (configfile) {
        read_conf(configfile, &conf);
    }

    int r = tell_kernel_to_hook();
    if (r) {
        if (r == EAGAIN)
            FATAL("Please wait a few seconds for Proximac release resources in kernel (normally in 10 sec)");
        else
            FATAL("kernel cannot hook this PID due to various reasons");
    }

    if (daemon == 1) {
        init_daemon();
    }

    struct sockaddr_in bind_addr;
    loop = malloc(sizeof *loop);
    uv_loop_init(loop);
    listener_t* listener = calloc(1, sizeof(server_ctx_t));
    listener->handle.data = listener;
    uv_tcp_init(loop, &listener->handle);
    uv_tcp_nodelay(&listener->handle, 1);

    r = uv_ip4_addr("127.0.0.1", conf.proximac_port, &bind_addr);
    if (r)
        LOGE("Translate address error");
    r = uv_tcp_bind(&listener->handle, (struct sockaddr*)&bind_addr, 0);
    if (r)
        LOGI("Bind error");
    r = uv_listen((uv_stream_t*)&listener->handle, 128 /*backlog*/, server_accept_cb);
    if (r)
        LOGI("Listen error");
    LOGI("Listening on %d", conf.proximac_port);

    signal(SIGPIPE, SIG_IGN);
    uv_signal_t sigint, sigstp, sigkil, sigterm;
    sigkil.data = loop;
    sigint.data = loop;
    sigstp.data = loop;
    sigterm.data = loop;
    uv_signal_init(loop, &sigint);
    uv_signal_init(loop, &sigstp);
    uv_signal_init(loop, &sigkil);
    uv_signal_init(loop, &sigterm);
    uv_signal_start(&sigint, signal_handler_ctl_z, SIGKILL);
    uv_signal_start(&sigint, signal_handler_ctl_c, SIGINT);
    uv_signal_start(&sigstp, signal_handler_ctl_z, SIGTSTP);
    uv_signal_start(&sigterm, signal_handler_ctl_z, SIGTERM);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    free(loop);

    return 0;
}

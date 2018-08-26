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
#include "socks5.h"
#include "utils.h"

static void sock_connect_to_remote_cb(uv_connect_t* req, int status);
static void sock_remote_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf);
static void sock_remote_write_cb(uv_write_t* req, int status);
extern conf_t conf;

static void sock_connect_to_remote_cb(uv_connect_t* req, int status)
{
    server_ctx_t* server_ctx = (server_ctx_t*)req->data;
    if (status) {
        // cleanup
        if (status != UV_ECANCELED) {
            TRY_CLOSE(server_ctx, &server_ctx->remote_handle, remote_after_close_cb);
        }
        
        LOGE("Fail connect to remote server: status=%d", status);
        free(req);
        return;
    }

    LOGI("connect to remote server: status=%d", status);
    uv_read_start(req->handle, remote_alloc_cb, sock_remote_read_cb);

    write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
    wr->req.data = server_ctx;

    char* socks5req = malloc(3);
    socks5req[0] = 0x05;
    socks5req[1] = 0x01;
    socks5req[2] = 0x00;
    wr->buf = uv_buf_init(socks5req, 3);

    uv_write(&wr->req, (uv_stream_t*)&server_ctx->remote_handle, &wr->buf, 1, sock_remote_write_cb);
}

static void sock_remote_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf)
{
    server_ctx_t* server_ctx = stream->data;
    if (nread <= 0) {
        if (nread == 0) {
            if (buf->len > 0)
                free(buf->base);
            return;
        }
        TRY_CLOSE(server_ctx, &server_ctx->remote_handle, remote_after_close_cb);
    } else {
        if (server_ctx->remote_stage == 0) {
            if (server_ctx->remote_auth_stage == 0) {
                if ((buf->base[0] == 0x05 && buf->base[1] == 0x00)) {
                    LOGD("negotiate successfully!");
                    goto neg_ok;
                } else if (buf->base[0] == 0x05 && buf->base[1] == 0x02) {
                    LOGD("socks5 server response 05 01 auth is required (OK)");
                    // now send auth. info to SOCKS5 proxy
                    write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
                    wr->req.data = server_ctx;
                    unsigned char username_len = strlen(conf.username);
                    unsigned char password_len = strlen(conf.password);
                    int len = 1 /* fixed 1 byte */ + 2 /* 2 bytes for username and password */ + username_len + password_len;
                    char* socks5req = malloc(len);
                    socks5req[0] = 0x01; /* version of auth */
                    socks5req[1] = username_len;
                    memcpy(socks5req + 2, conf.username, username_len);
                    socks5req[2 + username_len] = password_len;
                    memcpy(socks5req + 2 + username_len + 1, conf.password, password_len);
                    wr->buf = uv_buf_init(socks5req, len);
                    uv_write(&wr->req, (uv_stream_t*)&server_ctx->remote_handle, &wr->buf, 1, sock_remote_write_cb);
                    server_ctx->remote_auth_stage = 1;
                }
            } else if (server_ctx->remote_auth_stage == 1) {
                if (buf->base[0] == 0x01 && buf->base[1] == 0x00) {
                    LOGD("auth succeed!");
                    goto neg_ok;
                } else {
                    LOGD("auth fail: error username or password!");
                    TRY_CLOSE(server_ctx, &server_ctx->remote_handle, remote_after_close_cb);
                    free(buf->base);
                    return;
                }
            }
        } else if (server_ctx->remote_stage == 1) {
            if (buf->base[0] == 0x05) {
                LOGD("socks5 server works");
                server_ctx->server_stage = 1;
                write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
                if (server_ctx->buf_len) {
                    char* tmpbuf = malloc(server_ctx->buf_len);
                    memcpy(tmpbuf, server_ctx->buf, server_ctx->buf_len);
                    free(server_ctx->buf);
                    server_ctx->buf = NULL;
                    wr->req.data = server_ctx;
                    wr->buf = uv_buf_init(tmpbuf, (unsigned int)server_ctx->buf_len);
                    uv_write(&wr->req, (uv_stream_t*)&server_ctx->remote_handle, &wr->buf, 1, sock_remote_write_cb);
                }
                uv_read_start((uv_stream_t*)&server_ctx->server_handle, server_alloc_cb, server_read_cb);
                server_ctx->remote_stage = 2;
            }
        } else if (server_ctx->remote_stage == 2) {
            write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
            wr->req.data = server_ctx;
            wr->buf = uv_buf_init(buf->base, (unsigned int)nread);
            uv_write(&wr->req, (uv_stream_t*)&server_ctx->server_handle, &wr->buf, 1, sock_remote_write_cb);
        }
    }
    return;

neg_ok:
    server_ctx->remote_stage = 1;
    write_req_t* wr = (write_req_t*)malloc(sizeof(write_req_t));
    wr->req.data = server_ctx;
    int len = 4 + 1 + server_ctx->addrlen + sizeof(server_ctx->port);
    char* socks5req = malloc(len);
    socks5req[0] = 0x05;
    socks5req[1] = 0x01;
    socks5req[2] = 0x00;
    socks5req[3] = 0x03;
    socks5req[4] = server_ctx->addrlen;
    memcpy(socks5req + 5, server_ctx->remote_addr, server_ctx->addrlen);
    uint16_t port = htons(server_ctx->port);
    memcpy(socks5req + 5 + server_ctx->addrlen, &port, sizeof(server_ctx->port));
    wr->buf = uv_buf_init(socks5req, len);
    
    uv_write(&wr->req, (uv_stream_t*)&server_ctx->remote_handle, &wr->buf, 1, sock_remote_write_cb);
}

static void sock_remote_write_cb(uv_write_t* req, int status)
{
    write_req_t* wr = (write_req_t*)req;
    server_ctx_t* server_ctx = req->data;
    if (status) {
        if (status != UV_ECANCELED) {
            LOGW("remote_write_cb TRY_CLOSE");
            if (req->handle == &server_ctx->server_handle) {
                TRY_CLOSE(server_ctx, &server_ctx->server_handle, server_after_close_cb);
            } else {
                TRY_CLOSE(server_ctx, &server_ctx->remote_handle, remote_after_close_cb);
            }
        }
    }

    assert(wr->req.type == UV_WRITE);
    /* Free the read/write buffer and the request */
    free(wr->buf.base);
    free(wr);
}

struct proxy_server sock_proxy = {
    .remote_write_cb = sock_remote_write_cb,
    .remote_read_cb = sock_remote_read_cb,
    .connect_to_remote_cb = sock_connect_to_remote_cb,
};

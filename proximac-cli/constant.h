#ifndef _CONSTANT_H
#define _CONSTANT_H

#define BUF_SIZE 2048
#define CTL_CLOSE 0x04
#define CTL_INIT 0x01
#define CTL_NORMAL 0

#define LOCALHOST "127.0.0.1"

// packet related MACROs
#define MAX_PKT_SIZE 8192
#define ID_LEN 4
#define PKT_LEN 2
#define RSV_LEN 1
#define DATALEN_LEN 2
#define ATYP_LEN 1
#define ADDRLEN_LEN 1
#define PORT_LEN 2
#define HDR_LEN (ID_LEN + RSV_LEN + DATALEN_LEN)
#define EXP_TO_RECV_LEN (ID_LEN + RSV_LEN + DATALEN_LEN)

// remote connection status MACROs
#define RC_OFF              0
#define RC_ESTABLISHING     1
#define RC_OK               2
#define MAX_RC_NUM          32

// PF sockopt
// NOTE: should align with the kernerl mode definiation
#define PROXIMAC_ON         1
#define HOOK_PID            2
#define PIDLIST_STATUS      3
#define PROXIMAC_OFF        4
#define NOT_TO_HOOK         5
#define PROXY_SERVER        6

enum ServerStag {
    INIT = 0, //
    CONNECTED = 1,
};

#endif /* CONSTANT_H */

//
//  jconf.h
//  jedisocks
//
//  Created by jedihy on 15-2-25.
//  Copyright (c) 2015年 jedihy. All rights reserved.
//

#ifndef jedisocks_jconf_h
#define jedisocks_jconf_h
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include "tree.h"

enum ProxyType {
    HTTP,
    SOCK
};

typedef struct {
    uint16_t localport;
    char* local_address;
    char* proximac_listen_address;
    char* process_name;
    char* username;
    char* password;
    uint16_t proximac_port;
    int pid;
    int total_process_num;
    int vpn_mode;
    int proxyapp_hash;
    enum ProxyType type; // proxyType
} conf_t;

extern void read_conf(char* configfile, conf_t* conf);
#endif

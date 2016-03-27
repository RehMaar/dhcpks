#pragma once

#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <net/sock.h>


#include <linux/kernel.h>
#include <linux/types.h>

#define MAX_MAC_ADDR       6
#define MAX_DHCP_OPTS      19

enum {
    IP_SERVER = 0,
    IP_MASK,
    IP_RANGE_MIN,
    IP_RANGE_MAX,
    DEFAULT_LEASE,   
    MAX_LEASE,
    DEFAULT_TTL,
    IF_MTU,
    ROUTER,
    STATIC_ROUTERS,
    TIME_SERVER,
    DNS_SERVER,
    NAME_SERVER,
    NTP_SERVER,
    XWSFS_SERVER,
    XWSDM_SERVER,
    IF_HWADDR,
    IF_INDEX,
    IP_BROADCAST,
    RANGE,        /* For parsing. */
    OPTIONS        /* For parsing. */
};

struct cmdline_params 
{  
   char* if_name;
   char* ip_serv;
   char* mask;
   char* ip_range_min;
   char* ip_range_max;
   int default_lease;
};

struct opt_t 
{
   uint8_t* name;
   void* val;
   uint64_t len;
};


bool dhcps_set_config( struct cmdline_params* param );
void dhcps_destroy_config( void );

struct opt_t*  get_opt( int index );
uint32_t get_opt_val( int index );
char* get_if_name( void );

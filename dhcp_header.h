#pragma once
#include <linux/types.h>

#define BCAST_FLAG                  0x80
#define MAX_MAC_ADDR                6

#define DHCP_SERVER_PORT            67
#define DHCP_CLIENT_PORT            68

#define DHCP_SNAME_MAX_SIZE         64 
#define DHCP_FILE_MAX_SIZE          128
#define DHCP_OPTION_MAX_SIZE        308 /* RFC-2131 page 10 ( 312 - MAGIC). */
#define DHCP_CHADDR_MAX_SIZE        16

#define DHCP_MAGIC_COOKIE           0x63538263 


/*
 * struct dhcp_header
 * @op:      Message type;   
 * @htype:   Hardware address type;
 * @hlen:    Hardware address length;
 * @hops:    For relay-agents; 
 * @xid:     Transaction ID: random number;
 * @secs:    Seconds from the beginning of init;
 * @flags:   Nees-broadcast-answer flag;
 * @ciaddr:  Client IP;
 * @yiaddr:  Client IP from server;
 * @siaddr:  Server IP ( in reply );
 * @giaddr:  gateway IP ( relay-agents IP );
 * @chaddr:  Client hardware address;
 * @sname:   Server host name;
 * @file:    Boot file name;
 * @magic:   
 * @options: DHCP options; 
 */
#pragma pack( push, 1 )
struct dhcp_header 
{
   uint8_t  op; 
   uint8_t  htype;
   uint8_t  hlen;
   uint8_t  hops;
   uint32_t xid; 
   uint16_t secs;
   uint16_t flags;
   uint32_t ciaddr; 
   uint32_t yiaddr; 
   uint32_t siaddr; 
   uint32_t giaddr;
   uint8_t  chaddr[DHCP_CHADDR_MAX_SIZE];
   uint8_t  sname[DHCP_SNAME_MAX_SIZE]; 
   uint8_t  file[DHCP_FILE_MAX_SIZE]; 
   uint32_t magic;
   uint8_t  options[DHCP_OPTION_MAX_SIZE];
};
#pragma pack( pop )

/* DHCP op.*/
#define BOOTREQUEST                       1
#define BOOTREPLY                         2

/* DHCP Hardware type.*/
#define DHCP_HTYPE_ETHERNET               1  /* 10mb Eth. RFC 1340: ARP.*/
#define DHCP_HLEN                         6

/* DHCP options. */
#define DHCP_SUBNET_MASK                  1
#define DHCP_ROUTER                       3
#define DHCP_TIME_SERVER                  4
#define DHCP_NAME_SERVER                  5
#define DHCP_DOMANIN_NAME_SERVER          6
#define DHCP_HOST_NAME                    12
#define DHCP_DOMAIN_NAME                  15
#define DHCP_DEFAULT_IP_TTL               23
#define DHCP_MTU                          26
#define DHCP_BROADCAST                    28
#define DHCP_STATIC_ROUTERS               33 
#define DHCP_NTP_SERVER                   42
#define DHCP_XWINDOW_SYSTEM_FONT_SERVER   48
#define DHCP_XWINDOW_DISPLAY_MANAGER      49
#define DHCP_REQUESTED_IP_ADDRESS         50
#define DHCP_IP_ADDRESS_LEASE_TIME        51
#define DHCP_MESSAGE_TYPE                 53
#define DHCP_SERVER_IDENTIFIER            54
#define DHCP_REQUESTED_PARAMS             55
#define DHCP_RENEWAL_TIME                 58
#define DHCP_REBINDING_TIME               59
#define DHCP_CLIENT_INDETIFIER            61
#define DHCP_TFTP_SERVER_NAME             66
#define DHCP_BOOT_FILE_NAME               67
#define DHCP_END                          255 


/* DHCP message type. */
enum DHCP_TYPE {
   DHCPDISCOVER = 1, 
   DHCPOFFER    = 2, 
   DHCPREQUEST  = 3,
   DHCPDECLINE  = 4,
   DHCPACK      = 5,
   DHCPNAK      = 6,
   DHCPRELEASE  = 7, 
   DHCPINFORM   = 8  
};

void print_dhcp_header( struct dhcp_header* header );

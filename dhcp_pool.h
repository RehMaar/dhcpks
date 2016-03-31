#pragma once

#include <linux/time.h>
// ETH_... the same ? 
#define MAX_MAC_ADDR       6

/*
 * struct client_iptabel -- tabel of dhcp-clients.
 */

struct ip_mac_key
{
   uint8_t mac[MAX_MAC_ADDR];
   uint32_t ip;
};
struct iptable_record 
{
   struct iptable_record* next;
   uint8_t* options;
   union {
      struct ip_mac_key pair;
      uint8_t key[MAX_MAC_ADDR + sizeof(uint32_t)];
   } cl_ident;
   uint32_t opt_len;
};
struct lease_record 
{
   struct lease_record* next;
   uint32_t expire_time; /* Time of losing trust. */
   uint32_t lease_time;  /* Time range. */
   union {
      struct ip_mac_key pair; 
      uint8_t key[MAX_MAC_ADDR + sizeof(uint32_t)]; /* 10 byte */
   } cl_ident;
};

#define cl_mac cl_ident.pair.mac     
#define cl_ip  cl_ident.pair.ip      
#define cl_key cl_ident.key          


struct free_ip_record 
{
   struct free_ip_record* next;
   uint32_t ip;
};


void configure_pool( uint32_t ip_min, uint32_t ip_max );
void destroy_pool( void );
void clear_bad_address( uint32_t );

uint32_t get_free_address( void );
uint32_t register_ip( struct ip_mac_key*, uint32_t, uint8_t*, uint32_t );
uint32_t unregister_ip( uint32_t );
uint8_t* get_iptable_options( uint8_t* );

bool is_available_ip( uint32_t );

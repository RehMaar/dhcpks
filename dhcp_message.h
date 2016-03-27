#pragma once

#include "dhcp_header.h"
#include "dhcp_message.h"

#pragma pack( push, 4 )
struct address 
{
   uint32_t ip; 
   uint8_t mac[ MAX_MAC_ADDR ];
   uint16_t port;
};
#pragma pack(pop )
unsigned int dhcp_handle( struct dhcp_header* header );

#include <linux/module.h> 
#include <linux/init.h>

#include "dhcp_header.h"
#include "dhcp_message.h"
#include "dhcp_pool.h"
#include "dhcp_config.h"
#include "dhcp_socket.h"

#include "module_util.h"

#define ITERATE_OPTIONS( arr, offset, j, SWITCH... )                          \
for( j = 0; j < DHCP_OPTION_MAX_SIZE; j ++ ) {                                \
   switch( arr[offset] ) { SWITCH }                                           \
   offset = offset + arr[offset+1] + 2;                                       \
}                                                                  

static uint32_t dhcp_message_type( uint8_t* );
static void fill_option( uint8_t*, uint8_t*, uint32_t , uint32_t, uint32_t );
static void detect_dest(struct dhcp_header*, struct address*, uint32_t );

static uint32_t dhcp_discover( struct dhcp_header* );
static uint32_t dhcp_request( struct dhcp_header* );
static uint32_t dhcp_decline( struct dhcp_header* );
static uint32_t dhcp_inform( struct dhcp_header* );
static uint32_t dhcp_release( struct dhcp_header* );

static uint32_t dhcp_offer( struct dhcp_header*, uint8_t*, uint32_t, uint32_t, 
                            uint32_t );
static uint32_t dhcp_ack( struct dhcp_header*, uint8_t*, uint32_t, uint32_t, 
                          uint32_t );
static uint32_t dhcp_nak( struct dhcp_header* );

static DEFINE_SPINLOCK( lock_table );
static DEFINE_SPINLOCK( lock_config );

/* 
 * dhcp_handle - handle dhcp message
 * @header: dhcp header
 */
uint32_t dhcp_handle( struct dhcp_header* header )
{
    /* TODO: Be careful. */
   if( header->magic != DHCP_MAGIC_COOKIE ) 
    {
       PRINTALERT( "bad magic cookie.\n" );
       return 0;
    }
    switch( dhcp_message_type( header->options ) )
    {
       case DHCPDISCOVER:
             dhcp_discover( header );
             break;
       case DHCPREQUEST:
             dhcp_request( header );
             break;
       case DHCPDECLINE:
             dhcp_decline( header );
             break;
       case DHCPRELEASE:
             dhcp_release( header );
             break;
       case DHCPINFORM:
             dhcp_inform( header );
             break;
       default:
             printk( KERN_ALERT "broken header: unknown message type.\n" );
             return -1;
    }
    return 0;
}

/*
 * detect_dest - detect destination IP and MAC addresses. 
 * @header: dhcp header
 * @addr: buffer for addresses
 * @type: dhcp message type for DHCPNAK packets
 * NEED: select port.
 *       ciaddr != 0 => port 68 <=> send TO mac
 *       giaddr != 0 => port 67 <=> send TO ip 
 *       siaddr != 0 => port 68 <=> ???
 *       broadcast => port 68   <=> send BROADCAST
 */
static void detect_dest(struct dhcp_header* header,
                               struct address* addr, uint32_t type )
{
   memcpy( addr->mac, header->chaddr, MAX_MAC_ADDR);
   
   spin_lock(&lock_config);
   if( header->giaddr == 0 && type == DHCPNAK ) {
         addr->ip = get_opt_val( IP_BROADCAST );
         addr->port = DHCP_CLIENT_PORT;
   }
   else if( header->giaddr ) {
         addr->ip = header->giaddr;
         addr->port = DHCP_SERVER_PORT;
   }
   else if( header->ciaddr == 0 ) 
   {
         if( header->flags & BCAST_FLAG ) 
               addr->ip = get_opt_val( IP_BROADCAST );
         else 
               addr->ip = 0;
         addr->port = DHCP_CLIENT_PORT;
   }
   else {
        addr->ip = header->ciaddr;
        addr->port = DHCP_CLIENT_PORT; 
   }
   spin_unlock(&lock_config);
}

/*
 * dhcp_discover - handle DHCPDISCOVER message
 * @header: dhcp header
 * Answer: dhcp_offer only.
 * Set free IP. Doesn't set lease.  
 */
static uint32_t dhcp_discover( struct dhcp_header* header )
{
   uint8_t* opt = NULL;
   uint32_t ip = -1, lease = 0, opt_len = -1;
   int j, offset = 0;

#ifdef DEBUG
   PRINTINFO( "DHCPDISCOVER\n" );
#endif
   /*
    * Handle options field
    */
   ITERATE_OPTIONS( header->options, offset, j,

      case DHCP_REQUESTED_IP_ADDRESS:
               ip = ARR_TO_NUM( header->options, offset+2);         
               break;

      case DHCP_REQUESTED_PARAMS:         
               opt_len = header->options[offset+1];
               opt = KALLOCATE( uint8_t, opt_len );
               memcpy( opt, header->options+offset+2, opt_len*sizeof(uint8_t));
               break;

      case DHCP_IP_ADDRESS_LEASE_TIME:
               memcpy( &lease, header->options+offset+2, 
                       sizeof(uint8_t)*header->options[offset+1]);
               lease = htonl(lease);
               break;          

      case DHCP_END:
               goto send;
      default: 
               break;
   )

send:   
   /* If no IP requested, choose my own */
   if( ip == -1 ) {
         spin_lock( &lock_table);
            ip = get_free_address(); 
         spin_unlock( &lock_table);
   }
   else {
         if( !is_available_ip(ip) ) {
            spin_lock( &lock_table);
               ip = get_free_address();
            spin_unlock( &lock_table);
          }
   }
   dhcp_offer( header, opt, opt_len, ip, lease );

   if( opt ) kfree(opt);

   return 0;
}

/*
 * dhcp_request - handle DHCPREQUEST message
 * @header: dhcp header
 * Answer: DHCPACK, DHPCNAK 
 * 
 */
static uint32_t dhcp_request( struct dhcp_header* header )
{
   uint32_t tmp_serv_id = -1, tmp_req_ip = -1, opt_len = 0, lease = 0;
   uint8_t *opt = NULL;
   int j, offset = 0;
   struct ip_mac_key key;

#ifdef DEBUG
   PRINTINFO( "DHCPREQUEST\n" );
   print_dhcp_header( header );
#endif

   ITERATE_OPTIONS( header->options, offset, j,

      case DHCP_REQUESTED_IP_ADDRESS:
               tmp_req_ip = ARR_TO_NUM( header->options, offset+2);         
               break;

      case DHCP_SERVER_IDENTIFIER:            
               tmp_serv_id = get_opt_val( IP_SERVER );
               break;

      case DHCP_REQUESTED_PARAMS:           
               opt_len = header->options[offset+1];
               opt = KALLOCATE( uint8_t, opt_len );
               memcpy( opt, header->options+offset+2, opt_len);
               break;

      case DHCP_IP_ADDRESS_LEASE_TIME:
               memcpy( &lease, header->options+offset+2, 
                       sizeof(uint8_t)*header->options[offset+1]);
               lease = htonl(lease);
               break;
              
      case DHCP_END:
               goto handle;
      default: 
               break;
   )

handle:

   /* SELECTING -- choose options, save it and so on. */
     if((tmp_req_ip != -1)  && ( header->ciaddr == 0 )){
         spin_lock(&lock_config);
            if( tmp_serv_id != -1 )
               if( tmp_serv_id != get_opt_val(IP_SERVER) )
                   return 0;
         spin_unlock(&lock_config);
         
         if( !is_available_ip(tmp_req_ip) )  {
            
            spin_lock(&lock_table);
               tmp_req_ip = get_free_address();
            spin_unlock(&lock_table);
               
               if( tmp_req_ip == 0 ) {
                  PRINTALERT("No available addresses.\n" ); 
                  return -1;
               }
         }
         
         key.ip = tmp_req_ip;
         memcpy( &key.mac, header->chaddr, sizeof(uint8_t)*MAX_MAC_ADDR);
     }
   /* INIT_REBOOT -- return past options if it are still saved. */
     else if( tmp_serv_id == -1 && tmp_req_ip != -1 && header->ciaddr != 0 ){
         struct iptable_record *tmp_rec_iptab;
         if( !is_available_ip(tmp_req_ip )) {
            PRINTALERT( "Address %x is not available.\n", tmp_req_ip );
            return -1;
         }
         if( !is_correct_addr( tmp_req_ip ) ) {
            dhcp_nak( header );
            return 0;
         }
         
         if( opt != NULL ) {
            kfree( opt );
            opt = NULL;
         }
         spin_lock(&lock_table);
            tmp_rec_iptab = get_iptable_record( header->chaddr );
         spin_unlock(&lock_table);
         if(!tmp_rec_iptab) {
            PRINTALERT( "No record in iptable for address %x\n", tmp_req_ip );
            return -1;
         }

         opt = tmp_rec_iptab->options;
         opt_len = tmp_rec_iptab->opt_len;
         
         key.ip = tmp_req_ip;
         memcpy( &key.mac, header->chaddr, sizeof(uint8_t)*MAX_MAC_ADDR);
               
     }
   /* RENEWING / REBINDING -- update lease. */
     else if((tmp_req_ip == tmp_serv_id) == -1 && header->ciaddr != 0)  {
         key.ip = header->ciaddr;
         memcpy( &key.mac, header->chaddr, sizeof(uint8_t)*MAX_MAC_ADDR);
         if( opt != NULL ) {
               kfree( opt );
               opt = NULL;
         }
     }
   /* Ignore otherwise. */
     else {
         PRINTALERT( "IGNORE\n" );
         return 0;
     }
     /*
     if( lease == 0 ) {
       spin_lock(&lock_config);
         config_opt = get_opt( DEFAULT_LEASE );
         lease = ((uint32_t*)config_opt->val)[0];
       spin_unlock(&lock_config);
     }
   */
    PRINTALERT( "%s\n", opt == NULL ? "null" : "not null" );
    if( register_ip( &key, lease, opt, opt_len ) > 0 )
         dhcp_ack( header, opt, opt_len, tmp_req_ip, lease );

    if( opt != NULL ) 
           kfree( opt );

   return 0;
}

/*
 * dhcp_inform - handle DHCPINFORM message 
 * @header: dhcp header
 */
static uint32_t dhcp_inform( struct dhcp_header* header )
{
   uint32_t opt_len = 0;
   uint8_t* opt = NULL;
   int j, offset = 0;

   ITERATE_OPTIONS( header->options, offset, j,
      case DHCP_REQUESTED_PARAMS:           
               opt_len = header->options[offset+1];
               opt = KALLOCATE( uint8_t, opt_len );
               memcpy( opt, header->options+offset+2, opt_len);
               break;
      case DHCP_END:
               goto handle;
      default: 
               break;
   )
handle:   
#ifdef DEBUG
   PRINTINFO( "DHCPINFORM\n" );
   PRINTINFO( "From: %x\n", header->ciaddr );
#endif
   dhcp_ack( header, opt, opt_len, 0, 0 );
   return 0;
}

/*
 * dhcp_release - handle DHCPRELEASE message 
 * @header: dhcp header
 * TODO: delete all information from tables ( only lease table? ). 
 */
static uint32_t dhcp_release( struct dhcp_header* header )
{
   uint32_t ip = ntohl(header->ciaddr); /* To little endianness.*/
   uint32_t tmp, offset = 0, j;

#ifdef DEBUG
   PRINTINFO( "DHCPRELEASE\n" );
#endif
   ITERATE_OPTIONS( header->options, offset, j,
         case DHCP_SERVER_IDENTIFIER:            
               tmp = get_opt_val( IP_SERVER );
               if( tmp != (ARR_TO_NUM(header->options,(offset+2))))
               {
#ifdef DEBUG
                     PRINTINFO( "\tAnother choose.\n" );
#endif
                     goto exit; 
               }
               break;
         default:
               break;
   )

 spin_lock(&lock_table);
      unregister_ip( ip );
 spin_unlock(&lock_table);
   
exit:
   return 0;
}

/*
 * dhcp_decline - handle DHCPDECLINE message 
 * @header: dhcp header.
 * TODO: print alert if DECLINE comes
 *       add to trash_table 
 *       OR delete only the record of this mac. 
 */
static uint32_t dhcp_decline( struct dhcp_header* header )
{
   uint32_t tmp_ip = -1, offset = 0, tmp, j;
#ifdef DEBUG
   PRINTINFO( "DHCPDECLINE" );
#endif
   ITERATE_OPTIONS( header->options, offset, j,
         case DHCP_SERVER_IDENTIFIER:            
               tmp = get_opt_val( IP_SERVER );
               if(tmp != (ARR_TO_NUM(header->options,(offset+2)))) {
                     goto exit; 
               }
               break;
         case DHCP_REQUESTED_IP_ADDRESS:
               tmp_ip = ARR_TO_NUM( header->options, offset+2);         
               break;
         default:
               break;
   )        
   if( tmp_ip != -1 ) {
    spin_lock(&lock_table);
         clear_bad_address( tmp_ip );
    spin_unlock(&lock_table);
   }

exit:
   return 0;
}

/*
 * dhcp_offer - create repeat DHCPOFFER message
 * @header: dhcp header;
 * @opt:    options list;
 * @len:    length;
 * @ip:     requested IP.
 */
static uint32_t dhcp_offer( struct dhcp_header* header, uint8_t* opt,
                            uint32_t len, uint32_t ip, uint32_t lease )
{
   struct address addr;
   detect_dest( header, &addr, DHCPOFFER );
   if( lease == 0 ) {
      spin_lock(&lock_config);
         lease = get_opt_val( DEFAULT_LEASE );
      spin_unlock(&lock_config);
   }

   /* Set DHCP header for OFFER.*/
   header->op = BOOTREPLY;
   header->hops = 0;
   header->secs = 0;
   header->ciaddr = 0;
   /* To BIG ENDIANNESS. */
   header->yiaddr = htonl(ip); 
   header->siaddr = htonl(get_opt_val( IP_SERVER )); 

   fill_option( header->options, opt, len, lease, DHCPOFFER);

#ifdef DEBUG
   PRINTINFO( "DHCPOFFER\n" );
#endif
   send_msg( &addr, header );
   return 0;
}

/*
 * dhcp_ack - create repeat DHCPACK message 
 * @header: dhcp header;
 * @opt: options list;
 * @len: length;
 * @ip: requested IP.
 */
static uint32_t dhcp_ack( struct dhcp_header* header, uint8_t* opt, 
                          uint32_t len, uint32_t ip, uint32_t lease )
{
   struct address addr;

   detect_dest( header, &addr, DHCPACK );
   /* Case if this is an answer to the DHCPREQUEST message. */
   if( ip != 0 ) 
   { 
         /*
         if( lease == 0 ) {
               spin_lock(&lock_config);
                  config_opt = get_opt( DEFAULT_LEASE );
               spin_unlock(&lock_config);
               lease = ((uint32_t*)config_opt->val)[0];
         }
         */
         header->op = BOOTREPLY;
         header->hops = 0;
         header->secs = 0;
         header->ciaddr = 0;
         header->yiaddr = htonl(ip);
         header->siaddr = 0;
      
         fill_option( header->options, opt, len, lease, DHCPACK);
   }
   /* Response to the DCHPINFORM message. */
   else {
         header->op = BOOTREPLY;
         header->hops = 0;
         header->secs = 0;
         header->yiaddr = 0;
         header->siaddr = 0;
         fill_option( header->options, opt, len, 0, DHCPACK);
   }
#ifdef DEBUG
   PRINTINFO( "DHCPACK\n" );
#endif
   send_msg( &addr, header );

   return 0;
}

/*
 * dhcp_nak - create repeat DHCPNAK message
 * @header: dhcp header
 */
static uint32_t dhcp_nak( struct dhcp_header* header )
{
   struct address addr;
   
   detect_dest( header, &addr, DHCPNAK );
 
   header->op = BOOTREPLY;
   header->hops = 0;
   header->secs = 0;
   header->ciaddr = 0;
   header->yiaddr = 0;
   header->siaddr = 0;

   fill_option( header->options, NULL, 0, 0, DHCPACK );

#ifdef DEBUG
   PRINTINFO("DHCPNAK\n" );
#endif
   send_msg( &addr, header );
   return 0;
}

/*
 * fill_option - fill DHCP options fieled.
 * @options: DHCP options;
 * @list_opt: options list;
 * @opt_len: opt length;
 * @lease: lease time;
 * @type: DHCP message type.
 * If list_opt is NULL, only TYPE, SERVER IDENTIFIER and END options.
 */
static void fill_option( uint8_t* options, uint8_t* list_opt, uint32_t opt_len,
                         uint32_t lease, uint32_t type )
{
      uint32_t i, offset, index, tmp_int, lease_flag = 0;
      struct opt_t* tmp;

      if( !options ) return;

      memset( options, 0, DHCP_OPTION_MAX_SIZE );

      /* Set message type option. */
      options[0] = DHCP_MESSAGE_TYPE;
      options[1] = 1;
      options[2] = type;

      /* Set server identifier. */
      tmp = get_opt( IP_SERVER );
      options[3] = DHCP_SERVER_IDENTIFIER;
      options[4] = tmp->len;

      memcpy( options+5, tmp->val, tmp->len*sizeof(uint8_t) );
      offset = 9;
      if( list_opt )
      {
             for( i = 0 ; i < opt_len ; i++ )
             {
                  switch( list_opt[i] )
                  {
                        case DHCP_SUBNET_MASK:
                              index = IP_MASK;
                              break;
                        case DHCP_ROUTER:
                              index = ROUTER;
                              break;
                        case DHCP_TIME_SERVER:
                              index = TIME_SERVER;
                              break;
                        case DHCP_NAME_SERVER:
                              index = NAME_SERVER;
                              break;
                        case DHCP_DOMANIN_NAME_SERVER:
                              index = DNS_SERVER;
                              break;
                      /*
                      case DHCP_HOST_NAME:
                           index = HOST_NAME;
                           break;
                     */
                        case DHCP_DOMAIN_NAME:
                              continue; 
                        case DHCP_DEFAULT_IP_TTL:
                              index = DEFAULT_TTL;
                              break;
                        case DHCP_MTU:
                              index = IF_MTU;
                              break;
                        case DHCP_BROADCAST:
                              index = IP_BROADCAST;
                              break;
                        case DHCP_STATIC_ROUTERS:
                              index = STATIC_ROUTERS;
                              break;
                        case DHCP_NTP_SERVER:
                              index = NTP_SERVER;
                              break;
                        case DHCP_XWINDOW_SYSTEM_FONT_SERVER:
                              index = XWSFS_SERVER;
                              break;
                        case DHCP_XWINDOW_DISPLAY_MANAGER:
                              index = XWSDM_SERVER;
                              break;
                        case DHCP_IP_ADDRESS_LEASE_TIME:
                              index = DEFAULT_LEASE;
                              lease_flag = 1;
                              break;
                        /* TODO: Eval time properly, */
                        case DHCP_RENEWAL_TIME:
                              tmp_int = get_opt_val( DEFAULT_LEASE );
                              tmp_int = (uint32_t)(tmp_int/2);
                              options[offset++] = DHCP_RENEWAL_TIME;
                              options[offset++] = 4;
                              memcpy(options+offset, &tmp_int, sizeof(uint32_t));
                              offset += sizeof(uint32_t);
                              continue;
                        case DHCP_REBINDING_TIME:
                              tmp_int = get_opt_val( DEFAULT_LEASE );
                              tmp_int = (uint32_t)(tmp_int*7/8);
                              options[offset++] = DHCP_REBINDING_TIME;
                              options[offset++] = 4;
                              memcpy(options+offset, &tmp_int, sizeof(uint32_t));
                              offset += sizeof(uint32_t);
                              continue;
                        /* TODO: Hadnle this case properly. */
                        case DHCP_TFTP_SERVER_NAME:
                              continue;
                        case DHCP_BOOT_FILE_NAME:
                              continue; 
                        default:
                              continue;
               }

               tmp = get_opt( index );
               if( tmp->val ) {
                  options[offset++] = list_opt[i];
                  options[offset++] = tmp->len;
                  memcpy( options+offset, tmp->val, tmp->len*sizeof(uint8_t));
                  offset += tmp->len;
               }
         }
   }
   if( lease != 0 && lease_flag == 0 ) {
      options[offset++] = DHCP_IP_ADDRESS_LEASE_TIME;
      options[offset++] = 4;
      memcpy( options+offset, &lease, tmp->len*sizeof(uint8_t));
      offset += 4;
   }
   options[offset] = DHCP_END;
}

/*
 * dhcp_message_type -- detect DHCP message type from options.
 * @options: DHCP options field
 */
static uint32_t dhcp_message_type( uint8_t* options ) 
{
   int j, offset = 0;
   for( j = 0; j < DHCP_OPTION_MAX_SIZE; j ++ )
   {
      if( options[offset] == DHCP_MESSAGE_TYPE )
         return options[offset+2];
      offset = offset + options[offset+1] + 2;
   }
   return 0;
}

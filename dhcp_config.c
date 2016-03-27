#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>

#include <linux/slab.h>
#include <linux/kmod.h>

#include <linux/fs.h>
#include <asm/segment.h>
#include <asm/uaccess.h>
#include <linux/buffer_head.h>

#include <linux/netdevice.h>

#include "dhcp_header.h"
#include "dhcp_message.h"
#include "dhcp_config.h"
#include "module_util.h"

#define DHCP_SERVER_CONFIG_PATH     "/etc/dhcpks/dhcpks.conf"

#define CMP_LINE( str1, str2 ) if( strcmp( str1, str2 ) == 0 )

#define SET_VAL( type, index, param, value )                                  \
((type*)dhcps_options[index].val)[param] = value; 

#define PARSING_LOOP( index, delim, string, tok )                             \
i=0;                                                                          \
while((tok = strsep( &string, delim)) && i < dhcps_options[index].len )       \
     SET_VAL(uint8_t, index, i++, (uint8_t)atoi(tok) )                        \

#define SET_PROP( index, count, type )                                        \
if( dhcps_options[index].val == NULL )                                        \
{                                                                             \
    dhcps_options[index].val = KALLOCATE( type,(count));                      \
    dhcps_options[index].len = count;                                         \
}                                                                             \

#define SET_PROP_IF_DEFINED( index, count, string, DO )                       \
if(  string )                                                                 \
{                                                                             \
     SET_PROP( index, count, uint8_t )                                        \
     DO                                                                       \
}

#ifdef DEBUG
   static void print_opts( void );
#endif
static char* read_config( const char* filename );
static  int parse_dhcp_config( void );
static int atoi( char *str );

// TODO: after debug delete strings. 
static struct opt_t dhcps_options[MAX_DHCP_OPTS] = {
   { "ip_server",     NULL, 0 },
   { "ip_mask",       NULL, 0 },
   { "ip_range_min",  NULL, 0 },
   { "ip_range_max",  NULL, 0 },
   { "default_lease", NULL, 0 },
   { "max_lease",     NULL, 0 },
   { "default_ttl",   NULL, 0 },
   { "if_mtu",        NULL, 0 },
   { "router",        NULL, 0 },
   { "static router", NULL, 0 },
   { "time_servers",  NULL, 0 },
   { "dns_servers",   NULL, 0 },
   { "name_servers",  NULL, 0 },
   { "ntp_servers",   NULL, 0 },
   { "xwsfs_servers", NULL, 0 },
   { "xwsdm_servers", NULL, 0 }, 
   { "if_hwaddr",     NULL, 0 },
   { "if_index",      NULL, 0 },
   { "ip_broadcast",  NULL, 0 },
};


/* ``Fast'' access to the array's fields. My little OOP. */

/*
 * get_opt -- return struct opt_t ( dhcp_config.h ) from the 
 *            main config array. 
 */
struct opt_t* get_opt( int index )
{
   return &dhcps_options[index];
}

/*
 * get_opt_val -- return a value from the array as an integer.  
 */
uint32_t get_opt_val( int index )
{
   switch( index )
   {
      case DEFAULT_TTL:
      case IF_MTU:
      case DEFAULT_LEASE:
      case IF_INDEX:
      case MAX_LEASE:
         return dhcps_options[index].val != NULL ? 
                ((uint32_t*)(dhcps_options[index].val))[0] : 0;
      case IP_SERVER:
      case IP_MASK:
      case IP_RANGE_MIN:
      case IP_BROADCAST:
      case IP_RANGE_MAX:
        if( dhcps_options[index].val && dhcps_options[index].len == 4 ) 
            return ARR_TO_NUM(((uint8_t*)dhcps_options[index].val), 0);
      default:
         return 0;
   }
}
/* The end of my little OOP. */

/*
 * dhcps_set_config -- configure dhcpks.
 * @param -- input module's parameters. 
 */
bool dhcps_set_config( struct cmdline_params* param )
{
   struct net_device* dev;
   uint8_t *hwaddr;
   uint32_t mtu, ifindex, brdcast, ip, mask;
   parse_dhcp_config();
   
   read_lock(&dev_base_lock);
      if(!(dev = dev_get_by_name( &init_net, param->if_name )))
      {
         PRINTALERT( "cannot access to hardware address." );
         return false; 
      }
      hwaddr  = dev->dev_addr;  
      ifindex = dev->ifindex;  
      mtu     = dev->mtu;     
   read_unlock(&dev_base_lock);
   
   // BAD BAD BAD BAD BAD BAD BAD BAD
   if( dhcps_options[IF_HWADDR].val == NULL ) {
      dhcps_options[IF_HWADDR].val = KALLOCATE( uint8_t, MAX_MAC_ADDR );
      dhcps_options[IF_HWADDR].len = MAX_MAC_ADDR;
      memcpy( dhcps_options[IF_HWADDR].val, hwaddr, MAX_MAC_ADDR );
   }

   SET_PROP( IF_INDEX, (4), uint32_t )
   SET_VAL( uint32_t, IF_INDEX, 0, ifindex )

   SET_PROP( IF_MTU, ( 2 ), uint16_t )
   SET_VAL( uint16_t, IF_MTU, 0, mtu )
   PRINTINFO( "MTU %d ifindex %d", mtu, ifindex );
   if( param ) 
   {
       char* tok; int i = 0;
       SET_PROP_IF_DEFINED( 
          IP_SERVER, 4, param->ip_serv, 
          PARSING_LOOP( IP_SERVER, ".", param->ip_serv, tok )
       )
       SET_PROP_IF_DEFINED( 
          IP_MASK, 4, param->mask, 
          PARSING_LOOP( IP_MASK, ".", param->mask, tok )
       )
       SET_PROP_IF_DEFINED( 
          IP_RANGE_MIN, 4, param->ip_range_min, 
          PARSING_LOOP( IP_RANGE_MIN, ".", param->ip_range_min, tok )
       )
       SET_PROP_IF_DEFINED( 
          IP_RANGE_MAX, 4, param->ip_range_max, 
          PARSING_LOOP( IP_RANGE_MAX, ".", param->ip_range_max, tok )
       )
       SET_PROP_IF_DEFINED( 
          DEFAULT_LEASE, 1, param->default_lease, 
          SET_VAL( char, DEFAULT_LEASE, 0, param->default_lease )
       )
   }

   ip      = get_opt_val( IP_SERVER );
   mask    = get_opt_val( IP_MASK );
   brdcast = htonl( ip & mask );

   SET_PROP( IP_BROADCAST, ( 4 ), uint32_t )
   SET_VAL( uint32_t, IP_BROADCAST, 0, brdcast )

#ifdef DEBUG
   print_opts();
#endif
   return true;
}

/*
 * dhcps_destroy_config -- free all config's resources.
 */
void dhcps_destroy_config( void )
{
   int i;
   for( i = 0; i < MAX_DHCP_OPTS; i++ ) 
      if( dhcps_options[i].val ) kfree( dhcps_options[i].val );
}

static int hash( char* token )
{
   const int p = 31;
   int hash = 0, pow = 1, i = 0;
   while( token[i] != '\0')
   {
      hash += ( token[i] - 'a' + 1 ) *pow; 
      pow *= p; i++;
   }
   return hash;
}

/* 
 * find_index -- determines the type of the token while a configuration
 *               process.
 * @token -- one of the determinated strings; see parse_dhcp_config().  
 */
static int find_index( char* token )
{
   switch(hash( token ))
   {
      case 0x54794   : return IP_MASK;
      case 0x49d8dd  : return RANGE;            // ``range'' 
      case 0xe0ad42e : return DEFAULT_LEASE;    // ``default-lease''
      case 0x18bb9dab: return OPTIONS;          // ``option''
      case 0x1f07f51d: return IP_SERVER;
      case 0x2b9134c0: return DEFAULT_TTL;      // ``default_ttl''
      case 0xd90d3b51: return MAX_LEASE;        // ``max_lease''
      default: 
         return -1;
   }
}

static int parse_dhcp_config( void )
{
   char* conf = read_config( DHCP_SERVER_CONFIG_PATH );
   char* tmp = conf;

   if( conf ) 
   {
      char *token;
      while(( token = strsep( &conf, "\n")))
      {
         char *subtok, *tok, *stok;
         int index = 0, i = 0, j, count;
         
         subtok = strsep( &token, " ");        
         switch((index= find_index( subtok )))
         {
            case IP_MASK:
            case IP_SERVER:
                     SET_PROP( index, 4, uint8_t )
                     else
                     {
#ifdef DEBUG
                        PRINTALERT("errors while parsing config.\n");
#endif
                        continue;                                                      
                     }
                     subtok = strsep( &token, " ");
                     PARSING_LOOP( index, ".", subtok, tok )     
                     continue;
            case RANGE:
                     for( i = 0, count = 1; token[i] != '\0'; i++) 
                        if( token[i] == ' ' ) count++;            

                     if( count < 2 ) {
#ifdef DEBUG
                        PRINTALERT( "bad range.\n" );
#endif
                        continue;
                     }   
                     
                     SET_PROP( IP_RANGE_MIN, 4, uint8_t )
                     else                                                               
                     {                                                                 
#ifdef DEBUG
                        PRINTALERT("bad range.\n");
#endif
                        continue;                                                      
                     }
                     subtok = strsep( &token, " ");
                     PARSING_LOOP( IP_RANGE_MIN, ".", subtok, tok )
         
                     SET_PROP( IP_RANGE_MAX, 4, uint8_t )
                     else                                                               
                     {                                                                 
#ifdef DEBUG
                        PRINTALERT("bad range.\n");
#endif
                        continue;                                                      
                     }
                     subtok = strsep( &token, " ");
                     PARSING_LOOP( IP_RANGE_MAX, ".", subtok, tok )
                     continue;                                                      
            case DEFAULT_TTL:
                     tok = strsep( &token, " " );
                     SET_PROP( DEFAULT_TTL, (1), uint8_t )
                     else                                                               
                     {                                                                 
#ifdef DEBUG
                        PRINTALERT("errors while parsing config.\n");
#endif
                        continue;                                                      
                     }
                     SET_VAL( uint8_t, DEFAULT_TTL, 0, (uint8_t)atoi(tok) )
                     continue;
            case DEFAULT_LEASE:
            case MAX_LEASE:
                     tok = strsep( &token, " " );
                     SET_PROP( index, (4), uint8_t )
                     else                                                               
                     {                                                                 
#ifdef DEBUG
                        PRINTALERT("errors while parsing config.\n");
#endif
                        continue;                                                      
                     }
                     SET_VAL( uint32_t, index, 0, (uint32_t)atoi(tok) )
                     continue;                                                      

            case OPTIONS:
                     subtok = strsep( &token, " ");        
                     switch( atoi(subtok) )
                     {
                        case DHCP_ROUTER:       
                           index = ROUTER; break;
                        case DHCP_STATIC_ROUTERS:
                           index = STATIC_ROUTERS; break;
                        case DHCP_TIME_SERVER:  
                           index = TIME_SERVER; break;
                        case DHCP_NAME_SERVER:  
                           index = NAME_SERVER; break;
                        case DHCP_DOMANIN_NAME_SERVER:  
                           index = DNS_SERVER; break;
                        case DHCP_NTP_SERVER: 
                           index = NTP_SERVER; break;
                        case DHCP_XWINDOW_SYSTEM_FONT_SERVER:
                           index = XWSFS_SERVER; break;
                        case DHCP_XWINDOW_DISPLAY_MANAGER: 
                           index = XWSDM_SERVER; break;
                        default: break;
                     }
                     for( i = 0, count = 1; token[i] != '\0'; i++) 
                        if( token[i] == ' ' ) count++;
                     
                     SET_PROP( index, 4*count, uint8_t )
                     else                                                               
                     {                                                                 
#ifdef DEBUG
                        PRINTALERT("errors while parsing config: 3.\n");
#endif
                        continue;                                                      
                     }
         
                     i = 0;
                     while(i < count*4)
                     {
                        tok = strsep( &token, " ");
                        for( j = 0; j < 4; j++)
                        {
                           stok = strsep( &tok, ".");
                           SET_VAL( uint8_t, index, i++, (uint8_t)atoi(stok) )
                        }
                    }
            default:
                    continue;                                                      
         }
      }
      kfree( tmp );
   }
   return 0;
}

static char* read_config( const char* filename )
{
   struct file *f; 
   size_t n; 
   uint64_t l; 
   loff_t file_offset = 0; 
   char* buff = NULL;
    
   mm_segment_t fs = get_fs(); 
   set_fs( get_ds() ); 

   f = filp_open( filename, O_RDONLY, 0 ); 
   if( f < 0 ) 
      goto fail_open; 

    l = vfs_llseek( f, 0L, 2 ); 
    if( l <= 0 ) 
      goto fail; 

    buff = KALLOCATE( char, l );

    vfs_llseek( f, 0L, 0 ); 
    if( ( n = vfs_read( f, buff, l, &file_offset ) ) != l ) { 
        kfree( buff ); buff = NULL;
        goto fail; 
    } 
    buff[ n ] = '\0'; 

fail: 
    filp_close( f, NULL ); 
fail_open: 
    set_fs( fs ); 

   return buff;
}

#ifdef DEBUG
static void print_opts( void )
{
   int i, j;
   for( i = 0; i < MAX_DHCP_OPTS; i++ )
   {
      PRINTINFO( "Field %s: ", dhcps_options[i].name );
      switch( find_index( dhcps_options[i].name ) ) 
      {
         case DEFAULT_LEASE:
         case MAX_LEASE:
            printk( "%d ", ((uint32_t*)dhcps_options[i].val)[0] );
            break; 
         default: 
            for( j = 0; j < dhcps_options[i].len; j++ ) 
            {
               if( dhcps_options[i].val ) printk( "%d ", 
                                   ((uint8_t*)dhcps_options[i].val)[j] );
            }
      }
      printk( "\n");
   }
}
#endif

static bool  is_digit(char x)
{
    return (x >= '0' && x <= '9')? true: false;
}
static int atoi( char *str )
{
    int res = 0; int i = 0; 
    if (str == NULL) return 0;
    for (; str[i] != '\0'; ++i)
    {
        if (is_digit(str[i]) == false) return 0; 
        res = res*10 + str[i] - '0';
    }
    return res;
}

#include <linux/time.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>

#include "dhcp_header.h"
#include "dhcp_pool.h"
#include "dhcp_config.h"
#include "list_tamplate.h"
#include "module_util.h"

static bool lease_expire( uint32_t lease_time );
static uint32_t clean_lease( void );

/* Pointers to DHCP tables. */
struct lease_record* lease_table = NULL;
struct iptable_record* iptable = NULL; 
struct free_ip_record* free_ip_table = NULL;

static struct free_ip_record* last_available_addr = NULL;

static uint32_t min_available_addr;
static uint32_t max_available_addr;

static DEFINE_MUTEX( table_mutex );

/* Lease table. */

CREATE_LIST( struct lease_record, lease_record )
ADD_LIST( struct lease_record, lease_record, cl_ip )
DESTROY_LIST( struct lease_record, lease_record,
   kfree( tmp );   
)
DESTROY_RECORD_BY_NODE( struct lease_record, lease_record, 
   kfree( node );
)
DESTROY_RECORD( struct lease_record, lease_record, uint32_t, cl_ip,
  kfree(cur); 
)
PRINT_LIST( struct lease_record, lease_record,  "lease table",
  "%x - %x:%x:%x:%x:%x:%x = %d %d\n", tmp->cl_ip,
  tmp->cl_key[0], tmp->cl_ident.key[1],
  tmp->cl_key[2], tmp->cl_ident.key[3], 
  tmp->cl_key[4], tmp->cl_ident.key[5], 
  tmp->expire_time, tmp->lease_time
)


FIND_LIST( struct lease_record, lease_record, uint8_t*,
   int i;
   for( i = 0; i < MAX_MAC_ADDR; i++) {
         if( key[i] != tmp->cl_key[i] ) break;
   }
   if( i == MAX_MAC_ADDR ) return tmp;
)

FIND_LIST( struct lease_record, lease_record_by_ip, uint32_t,
   if( key == tmp->cl_ip ) return tmp;
)


/* IP table. */

CREATE_LIST( struct iptable_record, iptable_record, 
   (*node)->options = NULL;
   (*node)->opt_len = 0;
)
ADD_LIST( struct iptable_record, iptable_record, cl_ip )
DESTROY_RECORD( struct iptable_record, iptable_record, 
   uint32_t, cl_ip,
   if( cur->options ) kfree( cur->options );
   kfree( cur );
)
DESTROY_LIST( struct iptable_record, iptable_record, 
   if( tmp->options ) kfree( tmp->options );
   kfree( tmp );
)
FIND_LIST( struct iptable_record, iptable_record, uint8_t*,
   int i;
   for( i = 0; i < MAX_MAC_ADDR; i++) {
      if( key[i] != tmp->cl_key[i] ) break;
   }
   if( i == MAX_MAC_ADDR ) return tmp;
)
PRINT_LIST( struct iptable_record, iptable_record,  "ip table",
  "%x - %x:%x:%x:%x:%x:%x = %d\n", tmp->cl_ip,
  tmp->cl_key[0], tmp->cl_ident.key[1],
  tmp->cl_key[2], tmp->cl_ident.key[3], 
  tmp->cl_key[4], tmp->cl_ident.key[5], 
  tmp->opt_len
)


/* Free IP pool. */

CREATE_LIST( struct free_ip_record, free_ip_record )
ADD_LIST( struct free_ip_record, free_ip_record, ip )
DESTROY_RECORD( struct free_ip_record, free_ip_record, uint32_t, ip,
   kfree(cur);
)
DESTROY_LIST( struct free_ip_record, free_ip_record, kfree(tmp); )
FIND_LIST( struct free_ip_record, free_ip_record, uint32_t,
   if( key == tmp->ip ) return tmp;
)
PRINT_LIST( struct free_ip_record, free_ip_record,  "free ip table",
  " IP: %x\n", tmp->ip
)


/*
 * configure_pool -- create pool.
 * @ip_min: minimum ip address.
 * @ip_max: maximum ip address.
 */
void configure_pool( uint32_t ip_min, uint32_t ip_max ) 
{
   struct free_ip_record* tmp;
   uint32_t i;
   
   /* Save range. */
   min_available_addr = ip_min;
   max_available_addr = ip_max;

   /* Init free ip table. */
   create_free_ip_record( &free_ip_table );
   free_ip_table->ip = min_available_addr;
   last_available_addr = free_ip_table;

   for( i = min_available_addr+1; i <= max_available_addr; i++) 
   {
      create_free_ip_record( &tmp );
      tmp->ip = i;
      add_free_ip_record( &free_ip_table, tmp );
   }
#ifdef DEBUG
   print_free_ip_record( free_ip_table ); 
#endif
}

/*
 * destroy_pool -- free all allocated tables.
 */
void destroy_pool( void )
{
   destroy_list_free_ip_record( free_ip_table );
   destroy_list_iptable_record( iptable );
   destroy_list_lease_record( lease_table );
}


/*
 * is_available_ip -- check if ip is free.
 * @ip: requested ip.
 * Need to sync this shit. 
 */
bool is_available_ip( uint32_t ip )
{
   struct lease_record* tmp_lease_record; 

   mutex_lock( &table_mutex );
   if(!last_available_addr) 
      goto ERROR;

   if( ip >= max_available_addr && ip <= min_available_addr )
      goto ERROR;

   if( find_free_ip_record( free_ip_table, ip ) )
   {
      if( ip == last_available_addr->ip )   
         last_available_addr = last_available_addr->next == NULL ? 
                               free_ip_table : last_available_addr->next;
         goto SUCCESS;
   }
   if(( tmp_lease_record = find_lease_record_by_ip( lease_table, ip)))
   {
      if( !lease_expire(tmp_lease_record->expire_time) ) 
      {
         struct free_ip_record* tmp_free_ip_record;
         
         destroy_lease_record_by_node( tmp_lease_record, &lease_table );

         create_free_ip_record( &tmp_free_ip_record );
         tmp_free_ip_record->ip = ip;
         add_free_ip_record( &free_ip_table, tmp_free_ip_record );
         goto SUCCESS;
      }
   }

ERROR:
   mutex_unlock( &table_mutex);
   return false;

SUCCESS:
   mutex_unlock( &table_mutex);
   return true;
}

/*
 * get_free_address -- return free ip address.
 */
uint32_t get_free_address( void ) 
{
   uint32_t tmp = 0;
   if( last_available_addr ) {
   
      tmp = last_available_addr->ip;
      last_available_addr = last_available_addr->next == NULL ? free_ip_table :
                            last_available_addr->next;
   }
   else {
      /* Run free ip table creator from lease-table. */
   }
   print_free_ip_record( last_available_addr );
   return tmp;
}


/*
 * register_ip -- register requested ip.
 * @key: client address.
 * @lease: requested lease time.
 * @opts: list of requested options.
 * @len: length of the list.
 */
uint32_t register_ip( struct ip_mac_key* key, uint32_t lease,
                      uint8_t* opts, uint32_t len 
                    ) 
{
   /* 
      1. find ip in the free_ip_table and delete record.
      2. Add ip-mac & config to iptable.
      3. Add ip-mac & lease to lease_table.
      4. Return OK if all is good. What can go bad ? 
   */
   struct timeval cur_time;
   struct lease_record* record;
   //struct iptable_record* iptable_record;
   size_t i;

   if(!destroy_free_ip_record( key->ip, &free_ip_table ))
      return -1;

   create_lease_record( &record );
   record->cl_ip = key->ip;
   record->lease_time = lease;

   do_gettimeofday( &cur_time );
   record->expire_time = get_opt_val( MAX_LEASE ) + cur_time.tv_sec;

#ifdef DEBUG
   PRINTINFO( "REGISTER OLD. IP: %x MAX: %x %x %x %x %x %x\n", 
               key->ip, 
               key->mac[0],
               key->mac[1],
               key->mac[2],
               key->mac[3],
               key->mac[4],
               key->mac[5]);
#endif
   memcpy( &(record->cl_mac), key->mac, MAX_MAC_ADDR+sizeof(uint32_t));
   record->cl_ip = key->ip;
#ifdef DEBUG
   PRINTINFO( "REGISTER NEW. IP: %x MAX: %x %x %x %x %x %x\n", 
               record->cl_ip, 
               record->cl_mac[0],
               record->cl_mac[1],
               record->cl_mac[2],
               record->cl_mac[3],
               record->cl_mac[4],
               record->cl_mac[5]);
   PRINTINFO( "SOURCE: " );
   for( i = 0; i < MAX_MAC_ADDR; i++ )
   {
      printk( "%x ", key->mac[i] );
   }
   printk( " %x\n", key->ip );
   
   PRINTINFO( "DEST: " );
   for( i = 0; i < MAX_MAC_ADDR; i++ )
   {
      printk( "%x ", record->cl_mac[i] );
   }
   printk( " %x\n", record->cl_ip );
#endif
   //add_lease_record( &lease_table, record ); 
#ifdef DEBUG
   print_lease_record( lease_table );
#endif

   /* When lease will be fine.
   create_iptable_record( iptable_record );
   iptable_record->opt_len = len;
   memcpy( );
   */

   return 0;
}
/*
 * unregister_ip -- free lease_table and iptable.
 * @ip: ip to free. 
 */
uint32_t unregister_ip( uint32_t ip )
{
   struct free_ip_record* record;
   
   destroy_iptable_record( ip, &iptable );
   destroy_lease_record( ip, &lease_table );
   
   create_free_ip_record( &record );
   record->ip = ip;
   if( add_free_ip_record( &free_ip_table, record ) < 0 )
      PRINTINFO( "IP is already unregistred: %x", ip );
#ifdef DEBUG
   print_lease_record( lease_table );
   print_free_ip_record( free_ip_table );
#endif
   return 0;
}


/*
 * clear_bad_address -- delete address from tables.
 * @ip: bad ip.
 * @mac: mac address of the client. 
 */
void clear_bad_address( uint32_t ip, uint8_t* mac )
{
    
}

/*
 * clean_lease -- add to free_ip_table expired addresses. 
 */
static uint32_t clean_lease( void )
{
   return 0;
}

/*
 * lease_expire -- check lease expiration.
 * @lease_time: time to check.
 */
static bool lease_expire( uint32_t lease_time )
{
   struct timeval time;
   do_gettimeofday( &time );
   if( lease_time >= time.tv_sec )
      return true;
   return false;
}

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

/* It's a range of available addresses. */
static uint32_t min_available_addr;
static uint32_t max_available_addr;

/* SYNCOPOWER! */
static DEFINE_SPINLOCK( table_lock );


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
/* DEBUG. */
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


uint8_t* get_iptable_options( uint8_t* key ) {
   struct iptable_record *record =  find_iptable_record( iptable, key );
   if( record != NULL )
      return record->options;
   return NULL;
}

/*
 * is_available_ip -- check if ip is free.
 * @ip: requested ip.
 * Need to sync this shit. 
 */
bool is_available_ip( uint32_t ip )
{
   struct lease_record* tmp_lease_record; 
   spin_lock( &table_lock);
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
   spin_unlock( &table_lock);
   return false;

SUCCESS:
   spin_unlock( &table_lock);
   return true;
}

/*
 * get_free_address -- return free ip address.
 */
uint32_t get_free_address( void ) 
{
   uint32_t tmp = 0;
   
   spin_lock( &table_lock);
   if( last_available_addr ) {
   
      tmp = last_available_addr->ip;
      last_available_addr = last_available_addr->next == NULL ? free_ip_table :
                            last_available_addr->next;
   }
   else {
      clean_lease( );
   }
   spin_unlock( &table_lock);
   print_free_ip_record( last_available_addr );
   return tmp;
}


/*
 * register_ip -- register requested ip.
 * @key: client address.
 * @lease: requested lease time.
 * @opts: list of requested options.
 * @len: length of the list.
 * If address is already registered update lease time.
 */
uint32_t register_ip( struct ip_mac_key* key, uint32_t lease,
                      uint8_t* opts, uint32_t len 
                    ) 
{
   /* 
      1. find ip in the free_ip_table and delete record.
      2. Add ip-mac & config to iptable.
      3. Add ip-mac & lease to lease_table.
      4. Return OK if all is good. What can go bad ? ( Srly? )
   */
   struct timeval cur_time;
   struct lease_record* lease_record;
   
   struct iptable_record* iptable_record;

   if(( lease_record = find_lease_record_by_ip( lease_table, key->ip)) == NULL)
   {
      /* 1. */
      spin_lock( &table_lock);
         destroy_free_ip_record( key->ip, &free_ip_table );
      spin_unlock( &table_lock);

   
      create_lease_record( &lease_record );
      lease_record->cl_ip = key->ip;
      lease_record->lease_time = lease;

      do_gettimeofday( &cur_time );
      lease_record->expire_time = get_opt_val( MAX_LEASE ) + cur_time.tv_sec;

      memcpy( &(lease_record->cl_mac), key->mac, MAX_MAC_ADDR+sizeof(uint32_t));
      lease_record->cl_ip = key->ip;

      /* 3. */
      spin_lock( &table_lock);
         add_lease_record( &lease_table, lease_record ); 
      spin_unlock( &table_lock);
#ifdef DEBUG
      print_lease_record( lease_table );
#endif
   
      create_iptable_record( &iptable_record );
      iptable_record->opt_len = len;
      memcpy( iptable_record->options, opts, len);
      memcpy( &(iptable_record->cl_mac), key->mac, 
                                 MAX_MAC_ADDR+sizeof(uint32_t));
      iptable_record->cl_ip = key->ip;

      spin_lock( &table_lock);
         add_iptable_record( &iptable, iptable_record );
      spin_unlock( &table_lock);
   } 
   else {
      do_gettimeofday( &cur_time );
      lease_record->expire_time = get_opt_val( MAX_LEASE ) + cur_time.tv_sec;
      lease_record->lease_time = lease;
   }
   return 0;
}

/*
 * unregister_ip -- free lease_table and iptable.
 * @ip: ip to free. 
 */
uint32_t unregister_ip( uint32_t ip )
{
   struct free_ip_record* record;
   
   spin_lock( &table_lock);
   destroy_iptable_record( ip, &iptable );
   destroy_lease_record( ip, &lease_table );
   
   create_free_ip_record( &record );
   record->ip = ip;
   if( add_free_ip_record( &free_ip_table, record ) < 0 )
      PRINTINFO( "IP is already unregistred: %x", ip );
   spin_unlock( &table_lock);
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
void clear_bad_address( uint32_t ip )
{
   destroy_iptable_record( ip, &iptable );
   destroy_lease_record( ip, &lease_table );
}

/*
 * clean_lease -- add to free_ip_table expired addresses. 
 */
static uint32_t clean_lease( void )
{
   struct lease_record *cur_record = lease_table, *tmp; 
   uint32_t tmp_ip;
   while( cur_record ) { 
      tmp = cur_record->next;
      if( !lease_expire( cur_record->expire_time ) ) {
         tmp_ip = cur_record->cl_ip;
         destroy_lease_record_by_node( cur_record, &lease_table);
      }
      cur_record = tmp;
   }
   return 0;
}

/*
 * lease_expire -- check lease expiration.
 * @lease_time: time to check.
 * True if not expire ( what a twist! ).
 */
static bool lease_expire( uint32_t lease_time )
{
   struct timeval time;
   do_gettimeofday( &time );
   if( lease_time >= time.tv_sec )
      return true;
   return false;
}

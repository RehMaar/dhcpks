#include <linux/time.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>

#include "dhcp_header.h"
#include "dhcp_pool.h"
#include "dhcp_config.h"
#include "list_template.h"
#include "module_util.h"



/* Lease table. */
/* |  Expire time    |  Lease time  |  Identifier ( mac + ip ) |
 */

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
/*
 * |  Options[]  |   Options Len    |  Identifier   |
 * 
 * Save current client. Delete if WHAT?
 */

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
/*
 * | IP | 
 * 
 * All available IP addresses. 
 * Delete record if IP was requested. 
 * last_available_addr -- pointer to current record; goes through the list
 * cyclically.
 * Sorted by increasing ip.
 * Updates when no addresses are available by clearing lease table.
 */


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
  " IP: %x Next: %s %p\n", tmp->ip, tmp->next == NULL ? "null" : "not null", tmp->next
)


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

static DEFINE_SPINLOCK( lock_lease );
static DEFINE_SPINLOCK( lock_iptable );
static DEFINE_SPINLOCK( lock_freetable );

#ifdef DEBUG
void print_tables( void ) 
{
   print_free_ip_record( free_ip_table );
   print_iptable_record( iptable );
   print_lease_record( lease_table );
}
#endif
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
   free_ip_table->next = NULL;
   last_available_addr = free_ip_table;

   for( i = min_available_addr+1; i <= max_available_addr; i++) {
      create_free_ip_record( &tmp );
      tmp->ip = i;
      tmp->next = NULL;
      add_free_ip_record( &free_ip_table, tmp );
   }

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

struct iptable_record* get_iptable_record( uint8_t* key ) 
{
   struct iptable_record* rec;

   spin_lock(&lock_iptable);
      rec = find_iptable_record( iptable, key );
   spin_unlock(&lock_iptable);

   return rec;
}
uint8_t* get_iptable_options( uint8_t* key ) {
   struct iptable_record *record;
   //TODO: Need?
   spin_lock(&lock_iptable);
      record =  find_iptable_record( iptable, key );
   spin_unlock(&lock_iptable);

   if( record != NULL )
      return record->options;
   return NULL;
}

bool is_available_ip( uint32_t ip ) {

   /* If it's not in the range -- return false.
    * If in free_ip_table -- return true.
    * If lease expire DO SOMETHING!
    */
   struct lease_record* tmp_rec;
   
   if( ip >= max_available_addr || ip <= min_available_addr ) 
      return false;
   
   if( last_available_addr == NULL ) {
      /* TODO: Update list. If NULL nevertheless, return false. */

      clean_lease( );
      return false;
   }

   if(( find_free_ip_record( free_ip_table, ip) != NULL )) {
    
      /* If ip is last in the list last available is next or the first. */
      if( ip == last_available_addr->ip ) {
         last_available_addr = last_available_addr->next == NULL ? 
                               free_ip_table : last_available_addr->next;
      }

      return true;
   } 

   // TODO:
   tmp_rec = find_lease_record_by_ip( lease_table, ip);
   if( tmp_rec != NULL ) {
      if( lease_expire( tmp_rec->expire_time ) ) {
         struct free_ip_record *tmp_free_rec = NULL ;

         destroy_lease_record_by_node( tmp_rec, &lease_table );
         create_free_ip_record( &tmp_free_rec );
         tmp_free_rec->ip = ip;
         tmp_free_rec->next = NULL;

         spin_lock(&lock_freetable);
            add_free_ip_record( &free_ip_table, tmp_free_rec );
         spin_unlock(&lock_freetable);

         return true;
      }
   }
   return false;
}


uint32_t get_free_address( void ) {
   uint32_t tmp = 0;

   if( last_available_addr != NULL ) {
      tmp = last_available_addr->ip;
      last_available_addr = last_available_addr->next == NULL ? free_ip_table :
                            last_available_addr->next;
   } else {
      /* Clear lease. */
      clean_lease( );
   }
   return tmp;
}

/*
 * If registered, then update lease. 
 */
uint32_t register_ip( struct ip_mac_key* key, uint32_t lease, uint8_t* opts, 
                      uint32_t opt_len)  {
                          
     /* 
      * 1. find ip in the free_ip_table and delete record.
      * 2. Add ip-mac & config to iptable.
      * 3. Add ip-mac & lease to lease_table.
      * 4. Return OK if all is good. What can go bad ? 
      * ( Srly? If something is bad, all fucks up. :3 )
      */
   struct timeval cur_time;
   struct lease_record* lease_record;
   struct iptable_record* iptable_record;

   if( key == NULL ) {
      PRINTALERT("Bad address for registration!\n");
      return -1;
   }
   lease_record = find_lease_record_by_ip( lease_table, key->ip );
   iptable_record = find_iptable_record( iptable, key->mac );
   /* Register. */
   if( iptable_record == NULL ) {

      spin_lock(&lock_freetable);
         destroy_free_ip_record( key->ip, &free_ip_table );
      spin_unlock(&lock_freetable);

      /* Lease. */
      if( lease_record == NULL )
         create_lease_record( &lease_record );

      lease_record->cl_ip = key->ip;
      lease_record->lease_time = lease;
      
      do_gettimeofday( &cur_time );
      lease_record->expire_time = get_opt_val( MAX_LEASE ) + cur_time.tv_sec;

      memcpy(&(lease_record->cl_mac),key->mac,MAX_MAC_ADDR+sizeof(uint32_t));
      lease_record->cl_ip = key->ip;

      /* If record is already here, nothing will happen, I hope. */
      spin_lock(&lock_lease);
         add_lease_record( &lease_table, lease_record ); 
      spin_unlock(&lock_lease);
      
      /* iptable. */
      create_iptable_record( &iptable_record );

      if( opts ) {
         iptable_record->options = KALLOCATE( uint8_t, opt_len); 
         iptable_record->opt_len = opt_len;
         memcpy( iptable_record->options, opts, opt_len);
      } else {
         iptable_record->opt_len = 0;
         iptable_record->options = NULL;
      }
      memcpy( &(iptable_record->cl_mac), key->mac, 
                                 MAX_MAC_ADDR+sizeof(uint32_t));

      iptable_record->cl_ip = key->ip;
      spin_lock(&lock_iptable);
        if( add_iptable_record( &iptable, iptable_record ) < 0 )
            PRINTINFO("Address has been already registered.\n");
      spin_unlock(&lock_iptable);

   } else { /* Update lease. */
      if( lease_record == NULL ) {
         PRINTALERT( "No record in lease table for updating!\n" );
         return -1;
      }
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
#ifdef DEBUG
   PRINTALERT( "Unregister" );   
#endif
   spin_lock(&lock_iptable);
      destroy_iptable_record( ip, &iptable );
   spin_unlock(&lock_iptable);

   create_free_ip_record( &record );
   record->ip = ip;
   record->next = NULL; 
   spin_lock(&lock_freetable);
      if( add_free_ip_record( &free_ip_table, record ) < 0 )
         PRINTINFO( "IP is already unregistred: %x", ip );
   spin_unlock(&lock_freetable);

   return 0;
}

/*
 * clear_bad_address -- delete address from tables.
 * @ip: bad ip.
 * @mac: mac address of the client. 
 */
void clear_bad_address( uint32_t ip )
{
   spin_lock(&lock_iptable);
      destroy_iptable_record( ip, &iptable );
   spin_unlock(&lock_iptable);
   spin_lock(&lock_lease);
      destroy_lease_record( ip, &lease_table );
   spin_unlock(&lock_lease);
}

/*
 * clean_lease -- add to free_ip_table expired addresses. 
 */
static uint32_t clean_lease( void )
{
   struct lease_record *cur_record = lease_table, *tmp; 
   struct free_ip_record* tmp_rec = NULL;
   uint32_t tmp_ip;


   while( cur_record ) { 
      tmp = cur_record->next;

      if( lease_expire( cur_record->expire_time ) ) {
         tmp_ip = cur_record->cl_ip; /* Huh? Why? */
         destroy_lease_record_by_node( cur_record, &lease_table);
         /* Add to free ip table. */
         create_free_ip_record( &tmp_rec );

         tmp_rec->ip = tmp_ip;
         tmp_rec->next = NULL;
         spin_lock(&lock_freetable);
            add_free_ip_record( &free_ip_table, tmp_rec );
         spin_unlock(&lock_freetable);
         tmp_rec = NULL;
      }

      cur_record = tmp;
   }
   last_available_addr = free_ip_table;
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
      return false;
   return true;
}

bool is_correct_addr( uint32_t ip ) 
{

   if( ip >= max_available_addr || ip <= min_available_addr ) 
      return false;
   return true;
}


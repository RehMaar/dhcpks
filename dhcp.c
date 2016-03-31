#include <linux/module.h> 
#include <linux/init.h>

#include <linux/slab.h>
#include <linux/kmod.h>

#include <linux/kthread.h>
#include <linux/sched.h>

#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>

#include "dhcp_config.h"
#include "dhcp_server.h"
#include "module_util.h"

#ifdef DEBUG
   static char* if_name = "eth0";
#else 
   static char* if_name = NULL; 
#endif
static char* ip_serv = NULL;
static char* mask = NULL;
static char* ip_range_min = NULL;
static char* ip_range_max = NULL;
static int default_lease = 0;

module_param( if_name,       charp, S_IRUGO );
module_param( ip_range_min,  charp, S_IRUGO );
module_param( ip_range_max,  charp, S_IRUGO );
module_param( default_lease, int,   S_IRUGO );

struct cmdline_params* params = NULL;

struct task_struct* thread = NULL;

static int __init start_server( void ) 
{
   
   PRINTINFO( "Loaded.\n" );
   if( if_name != NULL ) {
      
      params = KALLOCATE( struct cmdline_params, (1));
      // TODO: strcpy
      params->if_name       = if_name;
      params->ip_serv       = ip_serv;
      params->mask          = mask;
      params->ip_range_min  = ip_range_min;
      params->ip_range_max  = ip_range_max;
      params->default_lease = default_lease;
      thread = kthread_create( (void*)main_server, (void*)params, "main_server");
      wake_up_process( thread );
   }
   else {
      PRINTALERT( "interface name is required." );   
   }
   return 0;
}

static void __exit exit_server( void )
{
   if( thread != NULL ) 
         kthread_stop( thread );
   if( params != NULL )
         kfree( params );
   PRINTINFO("Remove module.\n" );  
}

module_init( start_server );
module_exit( exit_server );

MODULE_LICENSE( "GPL" );

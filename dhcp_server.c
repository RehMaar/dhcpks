#include <linux/module.h> 
#include <linux/init.h>

#include <linux/slab.h>
#include <linux/kmod.h>

#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/workqueue.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>

#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>

#include "dhcp_message.h"
#include "dhcp_header.h"
#include "dhcp_config.h"
#include "dhcp_server.h"
#include "dhcp_pool.h"
#include "dhcp_socket.h"

#include "module_util.h"

#define ANY_PORT        0
#define MAX_BUFFER_SIZE 1024

struct work_data_struct {
      struct work_struct work; 
      struct dhcp_header* header;
};

struct workqueue_struct *queue;


static void handle_msg( struct work_struct* work )
{
   struct work_data_struct* current_work = (struct work_data_struct*)work;

   if( dhcp_handle( current_work->header ) < 0 ) 
      PRINTALERT( "error while handling header.\n" );

   kfree( current_work->header );
   kfree( current_work );
}

void main_server( void* data  ) 
{   
   struct socket* sock = NULL;

   dhcps_set_config( (struct cmdline_params*)data );
   configure_pool( get_opt_val( IP_RANGE_MIN ), get_opt_val( IP_RANGE_MAX ) );

   create_socket( &sock );

   queue = create_workqueue( "queue" );
   
   /* TODO: before exit wait for input message. How to fix? */
   while(!kthread_should_stop())
   {
      struct work_data_struct* cur_work;
		set_current_state(TASK_INTERRUPTIBLE);
      
      cur_work         = KALLOCATE( struct work_data_struct, (1) );
      cur_work->header = KALLOCATE( struct dhcp_header, (1) );
  
      memset(cur_work->header, 0, sizeof( struct dhcp_header ));
      
      if(!recv_msg( sock, cur_work->header ))
      {
         PRINTALERT( "cannot receive message.\n" );
         kfree( cur_work->header );
         kfree( cur_work );
         break;
      }
      INIT_WORK( &cur_work->work, handle_msg);
      queue_work( queue, &cur_work->work);   
   }

   /* Destroy all resources. */
   flush_workqueue( queue );
   destroy_workqueue( queue );

   if( sock ) sock_release( sock );  

   dhcps_destroy_config();
   destroy_pool();

}

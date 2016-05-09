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

void main_server( void* data  ) 
{
   struct socket* sock = NULL;
   struct dhcp_header* header = NULL;

   dhcps_set_config( (struct cmdline_params*)data );
   configure_pool( get_opt_val( IP_RANGE_MIN ), get_opt_val( IP_RANGE_MAX ) );

   create_socket( &sock );


   /* TODO: before exit wait for input message. How to fix? */
   while(!kthread_should_stop()) {

      set_current_state(TASK_INTERRUPTIBLE);
      header = KALLOCATE( struct dhcp_header, (1));

      memset(header, 0, sizeof( struct dhcp_header ));
      if(!recv_msg( sock, header )) {
         PRINTALERT( "cannot receive message.\n" );
         break;
      }

      if( dhcp_handle( header ) < 0 )
         PRINTALERT( "error while handling header.\n" );
   }

   if( sock ) 
      sock_release( sock );

   dhcps_destroy_config();
   destroy_pool();
}

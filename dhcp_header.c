#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>

#include "dhcp_header.h"

void print_dhcp_header( struct dhcp_header* header ) 
{
   int i;
   printk( KERN_ALERT "OP: %x\n",  header->op );
   printk( KERN_ALERT "HTYPE: %x\n", header->htype );
   printk( KERN_ALERT "HLEN: %x\n",  header->hlen );
   printk( KERN_ALERT "HOPS: %x\n",  header->hops );
   printk( KERN_ALERT "XID: %x\n",  header->xid );
   printk( KERN_ALERT "SECS: %x\n",  header->secs );
   printk( KERN_ALERT "FLAGS: %x\n", header->flags );
   printk( KERN_ALERT "CIADDR: %x\n", header->ciaddr );
   printk( KERN_ALERT "YIADDR: %x\n", header->yiaddr );
   printk( KERN_ALERT "SIADDR: %x\n", header->siaddr );
   printk( KERN_ALERT "GIADDR: %x\n", header->giaddr );
   printk( KERN_ALERT "CHADDR: ");
   for( i = 0; i < DHCP_CHADDR_MAX_SIZE; i ++ ) {
      printk( "%x ", header->chaddr[i] );
   }
   printk( KERN_ALERT "SNAME:");
   for( i = 0; i < DHCP_SNAME_MAX_SIZE; i ++ ) {
      printk( "%x ", header->sname[i] );
   }
   printk( KERN_ALERT "FILE:" );
   for( i = 0; i < DHCP_FILE_MAX_SIZE; i ++ ) {
      printk( "%x ", header->file[i] );
   }
   printk( KERN_ALERT "MAGIC COOKIE: %x", header->magic );
   //for( i = 0; i < DHCP_MAGIC_COOKIE; i ++ ) {
   //   printk( "%x ", header->file[i] );
   //}
   printk( KERN_ALERT "OPTIONS: " );
   for( i = 0; i < DHCP_OPTION_MAX_SIZE; i ++ ) {
      printk( "%d ", header->options[i] );
   }
   printk( KERN_ALERT "\n" );
}

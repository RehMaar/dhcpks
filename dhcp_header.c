#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>

#include "dhcp_header.h"

void print_dhcp_header( struct dhcp_header* header ) 
{
   int i;
   printk( KERN_INFO "OP: %x\n",  header->op );
   printk( KERN_INFO "HTYPE: %x\n", header->htype );
   printk( KERN_INFO "HLEN: %x\n",  header->hlen );
   printk( KERN_INFO "HOPS: %x\n",  header->hops );
   printk( KERN_INFO "XID: %x\n",  header->xid );
   printk( KERN_INFO "SECS: %x\n",  header->secs );
   printk( KERN_INFO "FLAGS: %x\n", header->flags );
   printk( KERN_INFO "CIADDR: %x\n", header->ciaddr );
   printk( KERN_INFO "YIADDR: %x\n", header->yiaddr );
   printk( KERN_INFO "SIADDR: %x\n", header->siaddr );
   printk( KERN_INFO "GIADDR: %x\n", header->giaddr );
   printk( KERN_INFO "CHADDR: ");
   for( i = 0; i < DHCP_CHADDR_MAX_SIZE; i ++ ) {
      printk( "%x ", header->chaddr[i] );
   }
   printk( KERN_INFO "SNAME:");
   for( i = 0; i < DHCP_SNAME_MAX_SIZE; i ++ ) {
      printk( "%x ", header->sname[i] );
   }
   printk( KERN_INFO "FILE:" );
   for( i = 0; i < DHCP_FILE_MAX_SIZE; i ++ ) {
      printk( "%x ", header->file[i] );
   }
   printk( KERN_INFO "MAGIC COOKIE: %x", header->magic );
   //for( i = 0; i < DHCP_MAGIC_COOKIE; i ++ ) {
   //   printk( "%x ", header->file[i] );
   //}
   printk( KERN_INFO "OPTIONS: " );
   for( i = 0; i < DHCP_OPTION_MAX_SIZE; i ++ ) {
      printk( "%d ", header->options[i] );
   }
   printk( KERN_INFO "\n" );
}

//#include <linux/netdevice.h>
#include <linux/if.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/random.h>

#include "dhcp_message.h"
#include "dhcp_config.h"
#include "dhcp_server.h"
#include "dhcp_pool.h"
#include "dhcp_socket.h"

#include "module_util.h"


#define IPHDR_LEN    sizeof(struct iphdr )
#define ETHHDR_LEN   sizeof(struct ethhdr)
#define UDPHDR_LEN   sizeof(struct udphdr)
#define DHCPHDR_LEN  sizeof(struct dhcp_header)
#define PSHDR_LEN    sizeof(struct pshdr)


/* For header's check sum. */

struct pshdr 
{
   uint32_t source, dest;
   uint8_t zero, proto;
   uint16_t length;
};

static void send_client(struct address*, struct dhcp_header*, int );
static void send_frame( struct address*, struct dhcp_header* );
static uint16_t check_sum( void*, uint32_t );


unsigned int inet_addr( char* source )
{
   int a1, a2,a3,a4;
   unsigned char dest[4];
   sscanf(source,"%d.%d.%d.%d",&a1,&a2,&a3,&a4);
   dest[0]=a1; dest[1]=a2; dest[2]=a3; dest[3]=a4;
   return *(unsigned int*)dest;
}

/* 
 * recv_msg -- listen for input requests. 
 * @sock:   earlier created socket;
 * @header: allocated buffer for a dhcp header.
 */
bool recv_msg( struct socket* sock, struct dhcp_header* header )
{
   struct sockaddr_in caddr;
   struct msghdr msg;
   struct kvec iov;
   int size = 0;
   const int len = sizeof( struct dhcp_header );

   CREATE_IOV( header, len )
   CREATE_MSGHDR( &caddr, sizeof( struct sockaddr_in) )

   size = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);
#ifdef DEBUG
   if( size < 0 )
   {
      PRINTALERT( "receive message error: %d.\n", size );
      return false;
   }
   PRINTINFO( "message was received.\n" );
#endif
   return true;
}

/*
 * create_socket -- init a socket.
 * @sock: a pointer to a target socket. 
 */
bool create_socket( struct socket** sock )
{
   struct sockaddr_in saddr;
   int err, val = 0;

   *sock = KALLOCATE( struct socket, (1) );

   CREATE_SOCKADDR_IN(saddr, AF_INET, htons( DHCP_SERVER_PORT ), 
                      htonl( INADDR_ANY )
   )
   CREATE_SOCKET( err, val, (*sock), saddr, PF_INET, SOCK_DGRAM, IPPROTO_UDP, 
                  SO_REUSEADDR, sock_release( *sock ); return false;
   )
   return true;
}  

/*
 * send_msg -- choose the sending way and send a message at last.
 * @addr:   target address' information;
 * @header: DHCP header.
 */
void send_msg( struct address* addr, struct dhcp_header* header )
{
   uint32_t brd = get_opt_val( IP_BROADCAST );
   if( addr->ip == brd )
   {
      /* Send broadcast. */
      PRINTINFO( "Send Broadcast %x.", addr->ip);
      send_client( addr, header, SO_BROADCAST );
   }
   else if( addr->ip == 0 )
   {
      /* Send to MAC. */
      PRINTINFO( "Send MAC.");
      send_frame( addr, header );
   }
   else 
   {
      /* Send to IP. */   
      PRINTINFO( "Send IP: %x.", addr->ip);
      send_client( addr, header, SO_REUSEADDR );
   }
}

/* 
 * send_client -- send a unicast or broadcasr message.
 * @addr:   target address' information;
 * @header: DHCP header;
 * @flag:   socket's flag, for broadcasting and unicasting separately.
 */
static void send_client( struct address* addr, struct dhcp_header* header,
                         int flag )
{
   struct socket* csock;
   struct sockaddr_in saddr, caddr;
   struct msghdr msg;
   struct kvec iov;

   uint16_t dest_port = addr->port;
   uint32_t dest_ip = flag == SO_BROADCAST ? htonl(get_opt_val( IP_BROADCAST )) 
                      : addr->ip;
   int size = 0;
   const int len  = sizeof( struct dhcp_header );
   int err, val = 1;

   csock = KALLOCATE( struct socket, (1));
   
   saddr.sin_addr.s_addr = htonl( INADDR_ANY );
   saddr.sin_family = PF_INET;
   CREATE_SOCKET( err, val, csock, saddr, PF_INET, SOCK_DGRAM, IPPROTO_UDP, 
                  flag, goto free; 
   )
   caddr.sin_addr.s_addr = dest_ip;
   caddr.sin_port = htons(dest_port);
   caddr.sin_family = PF_INET;

   CREATE_IOV( header, len )
   CREATE_MSGHDR( &caddr, sizeof( struct sockaddr_in ) )

#ifdef DEBUG
   PRINTINFO( "CLIENT PORT: %d IP: %x\n",  caddr.sin_port, caddr.sin_addr.s_addr); 
#endif
   size = kernel_sendmsg(csock, &msg, &iov, 0, len);
#ifdef DEBUG
   if( size < 0 )
      PRINTALERT( "send message error: %d.\n", -size);
   else
      PRINTINFO( "message send.\n" );
#endif
free:
   sock_release( csock );
}

static uint16_t check_sum( void* packet, uint32_t len ) 
{
   uint32_t left = len, sum = 0;
   uint16_t *ptr = (uint16_t*)packet;
   while( left > 1 )
   {
      sum += *ptr++; 
      left -= 2;
   }
   if( left == 1 )
      sum += htons(*(uint8_t*)ptr << 8 );
   sum = (sum >> 16 ) + ( sum & 0xffff );
   sum += ( sum >> 16 );
   return ~sum;
}

/* 
 * send_frame -- send ethernet frame on choosen hardware address
 * @addr: information of destination address
 * @header : DHCP-header. 
 */
static void send_frame( struct address* addr, struct dhcp_header* header )
{
   struct sockaddr_ll addr_ll;
   struct socket*     sock;
   struct kvec        iov;   
   struct msghdr      msg; 

   struct ethhdr *eth;
   struct iphdr  *ip;
   struct udphdr *udp;
   struct pshdr  ps;

   struct opt_t *hw_opt  = get_opt( IF_HWADDR ),
                *ttl_opt = get_opt( DEFAULT_TTL );

   uint32_t serv_ip = htonl(get_opt_val( IP_SERVER )),
            ifindex = get_opt_val( IF_INDEX );
   
   uint8_t *datagram, rand_ind, *chksum_pack, 
           *hwaddr = (uint8_t*)(hw_opt->val),
           ttl = ((uint8_t*)(ttl_opt->val))[0];

   int err, frame_len;

#ifdef DEBUG
   PRINTINFO( "INDEX: %x IP: %x TTL: %x ", ifindex, serv_ip, ttl );
#endif 

   frame_len = ETHHDR_LEN + IPHDR_LEN + UDPHDR_LEN + DHCPHDR_LEN;
   
   chksum_pack = KALLOCATE( uint8_t, (frame_len - ETHHDR_LEN));
   sock        = KALLOCATE(struct socket, (1));
   datagram    = KALLOCATE( uint8_t, frame_len );

   memset( datagram, 0, frame_len );
   eth = (struct ethhdr*)datagram; 
   ip  = (struct iphdr*)( datagram + ETHHDR_LEN );
   udp = (struct udphdr*)( datagram + ETHHDR_LEN + IPHDR_LEN );

   memcpy( datagram + ETHHDR_LEN + IPHDR_LEN + UDPHDR_LEN, header,DHCPHDR_LEN);

   if((err = sock_create_kern( PF_PACKET, SOCK_RAW,htons(ETH_P_ALL),&sock))<0 )
   {                                                              
      PRINTALERT("cannot create a socket: %d.\n", err ); 
      goto free;
   } 

   /* Set dest address. */
   memset( &addr_ll, 0, sizeof(struct sockaddr_ll));
   addr_ll.sll_family = PF_PACKET;
   addr_ll.sll_ifindex = ifindex;
   addr_ll.sll_pkttype = PACKET_OTHERHOST;
   addr_ll.sll_halen = ETH_ALEN;
   memcpy( addr_ll.sll_addr, addr->mac, MAX_MAC_ADDR); 

   /* Set ethhdr. */
   memcpy( eth->h_source, hwaddr,    MAX_MAC_ADDR );
   memcpy( eth->h_dest,   addr->mac, MAX_MAC_ADDR ); 
   eth->h_proto = htons(ETH_P_IP);
   
   /* Supposed error.  */
   get_random_bytes( &rand_ind, sizeof(uint8_t));
   ip->version  = 4;
   /* Internet Header Length ( number of 32-bit ). */ 
   ip->ihl      = 5; 
   /* Type Of Service ( quality of service). */
   ip->tos      = 0;
   ip->tot_len  = htons(frame_len - ETHHDR_LEN);
   ip->id       = htons(rand_ind);
    /* Frangment offset. */
   ip->frag_off = 0;
   ip->ttl      = ttl;
   ip->protocol = IPPROTO_UDP;
   ip->saddr    = serv_ip;
   ip->daddr    = addr->ip;
   ip->check    = 0;
  
   memcpy( chksum_pack, (uint8_t*)ip, IPHDR_LEN );
   ip->check =check_sum( chksum_pack, IPHDR_LEN ); 

   /* Pseudoheader for a udp's checksum. */

   ps.source = serv_ip;
   ps.dest   = addr->ip;
   ps.zero   = 0; 
   ps.proto  = IPPROTO_UDP;
   ps.length = htons( UDPHDR_LEN + DHCPHDR_LEN );

   udp->source = htons( DHCP_SERVER_PORT );
   udp->dest   = htons( addr->port ); 
   udp->len    = htons( UDPHDR_LEN + DHCPHDR_LEN );
   udp->check  = 0;

   memset( chksum_pack, 0, ( PSHDR_LEN+UDPHDR_LEN) );
   memcpy( chksum_pack, &ps,  PSHDR_LEN );
   memcpy( chksum_pack+PSHDR_LEN, udp, UDPHDR_LEN );
   udp->check = check_sum( chksum_pack, PSHDR_LEN+UDPHDR_LEN );

   CREATE_IOV( datagram, frame_len )
   CREATE_MSGHDR( &addr_ll, sizeof(struct sockaddr_ll) )

#ifdef DEBUG
   int i;
   printk( "Ethernet\n" );
   for( i = 0; i < frame_len; i ++ ) {
      printk( "%d ", datagram[i] );
      if( i % 20 == 0 ) printk( "\n");
      if( i == ETHHDR_LEN ) printk( "\nIP\n" );
      else if( i == ETHHDR_LEN + IPHDR_LEN ) 
            printk( "\nUDP\n");
      else if( i == ETHHDR_LEN + IPHDR_LEN + UDPHDR_LEN ){
         printk("\nDHCP\n");
      }
   }
#endif
   err = kernel_sendmsg(sock, &msg, &iov, 0, frame_len);
#ifdef DEBUG
   if( err < 0 ) 
      PRINTALERT( "send message error: %d.\n", -err);
   else
      PRINTINFO( "message send.\n" );
#endif

free:
   sock_release( sock );
   kfree( datagram );
}

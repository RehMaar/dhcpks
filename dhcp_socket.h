#pragma once

#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <net/sock.h>

#define ANY_PORT  0

#define CREATE_SOCKADDR_IN( sname, sfam, sport, saddr )                       \
   memset(&sname, 0, sizeof(sname));                                          \
   sname.sin_family       = sfam;                                             \
   sname.sin_port         = sport;                                            \
   sname.sin_addr.s_addr  = saddr;       

#define CREATE_SOCKET(err, val, socket, addr, pfam, socktype, prot, flag,FREE)\
   if((err = sock_create_kern( pfam, socktype, prot, &socket)) < 0 )          \
   {                                                                          \
      PRINTALERT("cannot create a socket: %d.\n", err );                      \
      FREE                                                                    \
   }                                                                          \
   if( flag != -1 )                                                           \
      if((err = kernel_setsockopt( socket, SOL_SOCKET,flag,                   \
                                     (char*)&val, sizeof(val)) < 0))          \
      {                                                                       \
         PRINTINFO("cannot setsockopt: %d.\n",err );                          \
         FREE                                                                 \
      }                                                                       \
   if((err = kernel_setsockopt( socket, SOL_SOCKET,SO_REUSEADDR,              \
                                   (char*)&val, sizeof(val)) < 0))            \
   {                                                                          \
      PRINTINFO("cannot setsockopt: %d.\n",err );                             \
      FREE                                                                    \
   }                                                                          \
if((err = kernel_bind( socket,(struct sockaddr*)&addr,                     \
                                             sizeof(struct sockaddr))) < 0)   \
   {                                                                          \
      PRINTALERT("cannot bind socket: %d.\n", err );                          \
      FREE                                                                    \
   }                                                                          


#define CREATE_MSGHDR( NAME, LEN )                                            \
   msg.msg_control = NULL;                                                    \
   msg.msg_controllen = 0;                                                    \
   msg.msg_flags = 0;                                                         \
   msg.msg_name = NAME;                                                       \
   msg.msg_namelen = LEN; 

#define CREATE_IOV( BASE, LEN )                                               \
   iov.iov_base = BASE;                                                       \
   iov.iov_len = LEN;


unsigned int inet_addr( char* );
bool create_socket( struct socket** sock );
bool recv_msg( struct socket*, struct dhcp_header* );
void send_msg( struct address*, struct dhcp_header* );

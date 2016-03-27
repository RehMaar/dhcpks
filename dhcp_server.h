#pragma once

#include <linux/in.h>
#include <linux/inet.h>
#include <linux/socket.h>
#include <net/sock.h>

void main_server( void* data  );

/*
************************ INFO LAND ******************************************
*   kernel_sendmsg( struct socket* socket, struct msghdr* msg, 
*                  struct kvec* iov, size_t num, size_t len  );
*  -- Сокет BSD
*  struct socket {
*     socket_state            state;   -- enum: CONNECTED etc
*     short                   type;    -- STREAM, DGRAM etc
*     unsigned long           flags;   -- 
*     struct socket_wq        *wq;     -- wait queue
*     struct file             *file;   -- file back pointer for gc
*     struct sock             *sk;     
*     const struct proto_ops  *ops;    -- proto spec sock ops
*  }; 
*  
*  --  
*  struct msghdr {
*     void              *msg_name;  -- UDP: ptr to dest sockaddr_in  
*     int                msg_namelen;
*     struct kvec       *msg_iovec; -- ptr to payload's blocks.
*     __kernel_size_t    msg_iovlen;
*     void              *msg_control;  -- control msgs 
*     __kernel_size_t    msg_controllen;
*     unsigned int       msg_flags;          
*  }; 
* struct kvec {
*     void  *iov_base; -- first block
*     size_t iov_len;
* };
*
*/

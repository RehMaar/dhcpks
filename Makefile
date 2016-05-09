EXTRA_CFLAGS=-Wall 
CURRENT=`uname -r`
KDIR=/lib/modules/$(CURRENT)/build/
PWD=$(shell pwd)
obj-m  := dhcpks.o

dhcpks-objs := dhcp.o dhcp_header.o dhcp_message.o dhcp_config.o \
               dhcp_server.o dhcp_pool.o dhcp_socket.o

all: 
	$(MAKE) -C $(KDIR) M=$(PWD) modules 
	make clean

clean: 
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order *.symvers 
	@rm -f .*.*.cmd *~ *.*~ TODO.* 
	@rm -fR .tmp* 
	@rm -rf .tmp_versions 

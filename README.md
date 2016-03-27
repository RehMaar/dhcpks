DHCP kernel server pre-alpha
============================

Weak attempt to implement DHCP server in kernel space for linux 3.16 just for <strike>fu</strike> educational purpose. 

Module parameters:            
1. if-name -- interface name [ must be ];                  
2. ip-serv -- server ip;                
3. mask -- mask, maybe;          
4. ip-range-min, ip-range-max -- range of available ip;        
5. default-lease -- default lease value, I suppose.               

Before test <b>must</b> create configuration file "/etc/dhcpks/dhcpks.conf". 
Format:           
1. For network mask: mask [ip]                                       
2. For server IP:    server [ip]                                           
3. For IP range: range  [min IP] [max IP]                                              
4. For default ttl: default-ttl [0-255]                                 
5. For default lease: default-lease [lease]                             
6. For max lease: max-lease [lease]                   
7. For DHCP options: options [option's code] [according to options numbers]               

If you want to use it, may the Luck will be with you. 

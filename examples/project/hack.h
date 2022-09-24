#include <stdio.h>
#include "net/ipv6/uip.h"

 void set_hack(int n);
 int get_hack();
 int get_version();
void set_version(int e);
/*the variable permit  to define the type of attack  

if hack = 0 then Increase attack
   hack = 1 then decrease attack
   hack = 2 then hello flooding attack
   hack = 3 then sybil attack
   hack = 4 then version number attack
   hack = 5 then worst parent attack
endif

in default hack = 0*/
    int hack ;	
    int  v ;
    uip_ipaddr_t nbr_list[10];
#include "project-conf.h"
#include "contiki.h"
#include "net/routing/rpl-classic/rpl-private.h"
#include "net/routing/rpl-classic/rpl-dag-root.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "hack.h"
#include "sys/energest.h"
#include "services/simple-energest/simple-energest.h"


#include <stdlib.h>
#include "attributes.h"

#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678
#define SEND_INTERVAL		  (60 * CLOCK_SECOND)
#define INIT_ATTACK (120 * CLOCK_SECOND)
// #define RX_CURRENT 18800ul
// #define TX_CURRENT 17400ul
// #define CPU_CURRENT 426ul
// #define LPM_CURRENT 20ul

/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static struct simple_udp_connection udp_conn;
static rpl_instance_t *current_instance ;
static rpl_rank_t legitimate_rank;
static rpl_rank_t illegitimate_rank;
// static uip_ds6_nbr_t *nbr; // list of neighbor
void dio_output(rpl_instance_t *instance, uip_ipaddr_t *uc_addr);
uip_ds6_nbr_t *uip_ds6_nbr_head(void);
uip_ds6_nbr_t *uip_ds6_nbr_next(uip_ds6_nbr_t *nbr);
  // static void simple_energest_step(void);
 void free_neighbor_list(void);
 rpl_rank_t increase_rank(rpl_rank_t base_rank);
 rpl_rank_t my_rank(void);
 void dio_output(rpl_instance_t *instance, uip_ipaddr_t *uc_addr);
 uip_ipaddr_t *rpl_parent_get_ipaddr(rpl_parent_t *nbr);
  static const char *rpl_ocp_to_str(int ocp);

 /*------------------------------------variables---------------------------------------*/
  static int ptosend = 0;
  static int ptorecev = 0;

/*---------------------------------------------------------------------------*/
static void udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{
    ptorecev++;

  LOG_INFO("Received response '%.*s' from ", datalen, (char *) data);
  LOG_INFO_6ADDR(sender_addr);
#if LLSEC802154_CONF_ENABLED
  LOG_INFO_(" LLSEC LV:%d", uipbuf_get_attr(UIPBUF_ATTR_LLSEC_LEVEL));
#endif
  LOG_INFO_("\n");

}

/*rpl mode operation*/
/*static const char *rpl_mop_to_str(int mop)
{
  switch(mop) {
    case RPL_MOP_NO_DOWNWARD_ROUTES:
      return "No downward routes";
    case RPL_MOP_NON_STORING:
      return "Non-storing";
    case RPL_MOP_STORING_NO_MULTICAST:
      return "Storing";
    case RPL_MOP_STORING_MULTICAST:
      return "Storing+multicast";
    default:
      return "Unknown";
  }
}*/

/*list of neighbord*/
 void neighbor_list()
{
  if(!current_instance->used) {
    LOG_INFO("-- Instance: None\n");
  }else{
    LOG_INFO(" -- version: %u -- OF: %s -- Rank: %u -- illegitiate_Rank: %u -- pref_parent: "
    ,current_instance->current_dag->version,rpl_ocp_to_str(current_instance->of->ocp),legitimate_rank, illegitimate_rank);
    LOG_INFO_6ADDR(rpl_parent_get_ipaddr(current_instance->current_dag->preferred_parent));
    printf(" -- Trickle_timer: current %u min %u max %u DIO_INIT %u DIO_OUT %u DIO_IN %u",
      current_instance->dio_intcurrent, current_instance->dio_intmin,
      (current_instance->dio_intmin + current_instance->dio_intdoubl), current_instance->dio_totint, current_instance->dio_totsend, current_instance->dio_totrecv);
   printf(" DIS_OUT: %u DIS_IN: %u DAO_OUT: %u DAO_IN: %u",dis_send, dis_recv, dao_send, dao_recv);
    
    // simple_energest_step();
    printf(" -- Period_summary 0 ( 60 seconds) -- Energie: %10lu -- Puissance %10lu",e, p);  
    printf(" -- DTSN_out: %u -- data_sent: %d -- data_receved: %d", current_instance->dtsn_out, ptosend, ptorecev);
     printf(" Liste_des_voisins: ");
    uip_ds6_nbr_t *nbr_l;
    for(nbr_l = uip_ds6_nbr_head(); nbr_l != NULL; nbr_l = uip_ds6_nbr_next(nbr_l)) {
      LOG_INFO_6ADDR(&nbr_l->ipaddr);
      if(uip_ds6_nbr_next(nbr_l) != NULL){printf("|");}
      
    }
    
    printf("\n");
    free_neighbor_list();
  }
  
}

/*free neighbord list */

  void free_neighbor_list()
{
  LOG_INFO("Liste des voisins:\n");
  uip_ds6_nbr_t *nbr_l;
  for(nbr_l = uip_ds6_nbr_head(); nbr_l != NULL; nbr_l = uip_ds6_nbr_next(nbr_l)) {
     uip_ds6_nbr_rm(nbr_l);
   
  }
}

/*increase rank */
  rpl_rank_t increase_rank(rpl_rank_t base_rank)
 {

 rpl_rank_t increment = current_instance->current_dag->instance->min_hoprankinc; 

  return base_rank + increment;
 }

 /*get rank */
  rpl_rank_t my_rank()
 {
  return current_instance->current_dag->rank;
 }
 
/*objectif function */
static const char *rpl_ocp_to_str(int ocp)
{
  switch(ocp) {
    case RPL_OCP_OF0:
      return "OF0";
    case RPL_OCP_MRHOF:
      return "MRHOF";
    default:
      return "Unknown";
  }
}

 
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(udp_client_process, ev, data)
{
  static struct etimer periodic_timer;
  static unsigned count;
  static char str[32];
  uip_ipaddr_t dest_ipaddr;
  current_instance = rpl_get_default_instance();
  legitimate_rank = my_rank();
  illegitimate_rank = increase_rank(legitimate_rank);
  set_hack(5);
  PROCESS_BEGIN();

  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);

  etimer_set(&periodic_timer, random_rand() % SEND_INTERVAL);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));      
    if(NETSTACK_ROUTING.node_is_reachable() && NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
      /* Send to DAG root */
      //status();
      
      LOG_INFO("Sending request %u to ", count);
      LOG_INFO_6ADDR(&dest_ipaddr);
      LOG_INFO_("\n");
      snprintf(str, sizeof(str), "hello %d", count);
      simple_udp_sendto(&udp_conn, str, strlen(str), &dest_ipaddr);
      count++;
      ptosend = (int)count;

      // sending diio message
      neighbor_list();

    } else {
      LOG_INFO("Not reachable yet\n");
      neighbor_list();
    }

    /* Add some jitter */
    etimer_set(&periodic_timer, SEND_INTERVAL
      - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));

  }


  PROCESS_END();
}
/*---------------------------------------------------------------------------*/

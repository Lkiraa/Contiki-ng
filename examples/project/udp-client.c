#include "project-conf.h"
#include "contiki.h"
#include "net/routing/rpl-classic/rpl-private.h"
#include "net/routing/rpl-classic/rpl-dag-root.h"
#include "net/routing/routing.h"
#include "random.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6-nbr.h"
#include "net/ipv6/uip-icmp6.h"



#include <stdlib.h>
#include <stdio.h>

#include "sys/log.h"
#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678
#define SEND_INTERVAL		  (60 * CLOCK_SECOND)

/*-----------------------------------prototypes-----------------------------------*/
uip_ds6_nbr_t *uip_ds6_nbr_head(void);
uip_ds6_nbr_t *uip_ds6_nbr_next(uip_ds6_nbr_t *nbr);
 void free_neighbor_list(void);
 rpl_rank_t increase_rank(rpl_rank_t base_rank);
 rpl_rank_t my_rank(void);
 uip_ipaddr_t *rpl_parent_get_ipaddr(rpl_parent_t *nbr);
 static const char *rpl_mop_to_str(int mop);
 static const char *rpl_ocp_to_str(int ocp);
/*-----------------------------------variables-----------------------------------*/

static struct simple_udp_connection udp_conn;
 rpl_instance_t *current_instance ;
 rpl_rank_t legitimate_rank;
 rpl_rank_t illegitimate_rank;
/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client");
AUTOSTART_PROCESSES(&udp_client_process);
/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
         const uip_ipaddr_t *sender_addr,
         uint16_t sender_port,
         const uip_ipaddr_t *receiver_addr,
         uint16_t receiver_port,
         const uint8_t *data,
         uint16_t datalen)
{

  LOG_INFO("Received response '%.*s' from ", datalen, (char *) data);
  LOG_INFO_6ADDR(sender_addr);
#if LLSEC802154_CONF_ENABLED
  LOG_INFO_(" LLSEC LV:%d", uipbuf_get_attr(UIPBUF_ATTR_LLSEC_LEVEL));
#endif
  LOG_INFO_("\n");

}

/*rpl mode operation*/
static const char *rpl_mop_to_str(int mop)
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
}

/*list of neighbord*/
 void neighbor_list()
{
  
  if(!current_instance->used) {
    LOG_INFO("-- Instance: None\n");
  }else{
    LOG_INFO("-- MOP: %s\n", rpl_mop_to_str(current_instance->mop));
    LOG_INFO("-- OF: %s\n", rpl_ocp_to_str(current_instance->of->ocp));
    LOG_INFO("-- legitiate Rank: %u\n", legitimate_rank);
    LOG_INFO("-- illegitiate Rank: %u\n", illegitimate_rank);
     LOG_INFO("--preferred parent: ");
    LOG_INFO_6ADDR(rpl_parent_get_ipaddr(current_instance->current_dag->preferred_parent));
    LOG_INFO("\nListe des voisins:\n");
    uip_ds6_nbr_t *nbr_l;
    for(nbr_l = uip_ds6_nbr_head(); nbr_l != NULL; nbr_l = uip_ds6_nbr_next(nbr_l)) {
      LOG_INFO_6ADDR(&nbr_l->ipaddr);
      printf("\n");
    }
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

 /*void status(){
  // status rpl

  LOG_INFO("RPL status:\n");
  if(!current_instance->used) {
    LOG_INFO("-- Instance: None\n");
  } else {
    LOG_INFO("-- Instance: %u\n", current_instance->instance_id);
    if(NETSTACK_ROUTING.node_is_root()) {
      LOG_INFO("-- DAG root\n");
    } else {
      LOG_INFO("-- DAG node\n");
    }
    LOG_INFO("-- DAG: ");
    LOG_INFO_6ADDR(&current_instance->current_dag->dag_id);
    LOG_INFO("\n, version %u\n", current_instance->current_dag->version);
    LOG_INFO("-- Prefix: ");
    LOG_INFO_6ADDR(&current_instance->current_dag->prefix_info.prefix);
    LOG_INFO("/%u\n", current_instance->current_dag->prefix_info.length);
    LOG_INFO("-- MOP: %s\n", rpl_mop_to_str(current_instance->mop));
    LOG_INFO("-- OF: %s\n", rpl_ocp_to_str(current_instance->of->ocp));
    LOG_INFO("-- Hop rank increment: %u\n", current_instance->min_hoprankinc);
    LOG_INFO("-- Default lifetime: %u seconds\n", current_instance->lifetime_unit);

    //LOG_INFO("-- State: %s\n", rpl_state_to_str(current_instance.current_dag->state));
    LOG_INFO("-- Preferred parent: ");
    if(current_instance->current_dag->preferred_parent) {
      LOG_INFO_6ADDR(rpl_parent_get_ipaddr(current_instance->current_dag->preferred_parent));
      LOG_INFO(" (last DTSN: %u)\n", current_instance->current_dag->preferred_parent->dtsn);
    } else {
      LOG_INFO("None\n");
    }
   LOG_INFO("-- Rank: %u\n", current_instance->current_dag->rank);
   LOG_INFO("-- liste of neighboard: \n");
    LOG_INFO("-- Lowest rank: %u (%u)\n", current_instance.current_dag->lowest_rank, current_instance.max_rankinc);
    LOG_INFO("-- DTSN out: %u\n", current_instance.dtsn_out);
    LOG_INFO("-- DAO sequence: last sent %u, last acked %u\n",
        current_instance.current_dag->dao_last_seqno, current_instance.current_dag->dao_last_acked_seqno);
    LOG_INFO("-- Trickle timer: current %u, min %u, max %u, redundancy %u\n",
      current_instance.current_dag->dio_intcurrent, current_instance.dio_intmin,
      current_instance.dio_intmin + current_instance.dio_intdoubl, current_instance.dio_redundancy);

  }
}*/


/*frrrrrrrrrrrrrrrrrrrrrrrrrr*/

/*static const char *rpl_state_to_str(enum rpl_dag_state state)
{
  switch(state) {
    case DAG_INITIALIZED:
      return "Initialized";
    case DAG_JOINED:
      return "Joined";
    case DAG_REACHABLE:
      return "Reachable";
    case DAG_POISONING:
      return "Poisoning";
    default:
      return "Unknown";
  }
}*/

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

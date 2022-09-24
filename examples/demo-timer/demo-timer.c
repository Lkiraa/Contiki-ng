#include "contiki.h"
#include "sys/clock.h"
#include "sys/timer.h"
#include "sys/etimer.h"
#include "sys/stimer.h"
#include "sys/ctimer.h"
#include "sys/rtimer.h"
#include "stdio.h"


static int counter;
static struct timer timer_timer;
static struct stimer stimer_timer;
static struct etimer etimer_timer;
static struct ctimer ctimer_timer;
static struct rtimer rtimer_timer;

PROCESS(demo_timer1, "demo timer stimer");
PROCESS(demo_timer2, "demo etimer");
PROCESS(demo_timer3, "demo ctime");
PROCESS(demo_timer4, "demo rtime");
AUTOSTART_PROCESSES(&demo_timer1, &demo_timer2, &demo_timer3, &demo_timer4);

static rtimer_clock_t timeout_rtimer = RTIMER_SECOND / 2;

void perform_ctime_callback(){

	printf("Process demo_timer3: ctimer callback called\n");
	if(counter>=2){
		printf("ctimer is stopped\n");
		ctimer_stop(&ctimer_timer);
	}
	else
		ctimer_reset(&ctimer_timer);
}

void perform_rtime_callback(){
	printf("Process demo_timer3: rtimer callback called\n");
	if(counter<2){
		rtimer_set(&rtimer_timer, RTIMER_NOW() + timeout_rtimer, 0, perform_rtime_callback, NULL);
	}
	else
		printf("rtimer is stopped\n"); 
}

// process timer and stimer

PROCESS_THREAD(demo_timer1, ev, data)
{
  PROCESS_BEGIN();
  counter = 0;
  clock_time_t t = clock_time();
  printf("Timer start: %lu \n", t);
  timer_set(&timer_timer, 3 * CLOCK_SECOND);
  stimer_set(&stimer_timer, 3);
  while(1){
    if(timer_expired(&timer_timer)){
      t = clock_time();
      printf("timer expired: %lu \n", t);
      timer_reset(&timer_timer);
      counter++;
    }
    if(stimer_expired(&stimer_timer)){
      t = clock_time();
      printf("stimer expired: %lu \n", t);
      stimer_reset(&stimer_timer);
      counter++;
    }
    if(counter>=2)
      break;
  }
  printf("demo_timer1 process end\n");
  PROCESS_END();
}

// process etimer 

PROCESS_THREAD(demo_timer2, ev, data)
{
  PROCESS_BEGIN();
  printf("demo etimer\n");
  clock_time_t t = clock_time();
  printf("etimer start: %lu \n", t);
  printf("set etimer 3 clock_second\n");
  etimer_set(&etimer_timer, 3 * CLOCK_SECOND);
  while(1){
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&etimer_timer));
    etimer_reset(&etimer_timer);
    if(counter>=2)
      break;
  }
  printf("demo_timer2 process end\n");
  PROCESS_END();
}

// process ctimer

PROCESS_THREAD(demo_timer3, ev, data)
{
  PROCESS_BEGIN();
  printf("demo ctime\n");
  while(1) {
    ctimer_set(&ctimer_timer, CLOCK_SECOND, perform_ctime_callback, NULL);
    PROCESS_YIELD();
  }
  PROCESS_END();
}
// process rtimer

PROCESS_THREAD(demo_timer4, ev, data)
{
  PROCESS_BEGIN();
  printf("demo rtime\n");
  while(1) {
    rtimer_set(&rtimer_timer, RTIMER_NOW() + timeout_rtimer, 0, perform_rtime_callback, NULL);
    PROCESS_YIELD();
  }
  PROCESS_END();
}
#include "contiki.h"
#include "sys/etimer.h"
#include "mycounter.h"

#include <stdio.h>

PROCESS(counter_process, "Counter process");
AUTOSTART_PROCESSES(&counter_process);
static struct etimer timer;
static int counter = 0;

PROCESS_THREAD(counter_process,ev, data){
	PROCESS_BEGIN();
	printf("Demo Counter\n");
	while(1){
		etimer_set(&timer, CLOCK_SECOND * 3);
		PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

		counter = next_counter(counter);
		printf("Counter: %d\n", counter);

	}
	PROCESS_END();
}



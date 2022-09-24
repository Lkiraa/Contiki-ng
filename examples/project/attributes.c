#include "attributes.h"
//dis
void dis_out(uint16_t i){
	dis_send = i;
}

void dis_in(uint16_t j){
	dis_recv = j;
}
//dio
void dio_in(uint16_t i){
	dio_recv = i;
}

void dio_out(uint16_t j){
	dio_send = j;
}

void dao_in(uint16_t i){
	dao_recv = i;
}

void dao_out(uint16_t j){
	dao_send = j;
}



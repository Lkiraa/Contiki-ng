CONTIKI_PROJECT = increase-rank-attack decrease-rank-attack worst-parent-attack sybil-attack hello-flooding-attack
PROJECT_SOURCEFILES += hack.c
PROJECT_SOURCEFILES += attributes.c
MODULES += $(CONTIKI_NG_NET_DIR)/routing/rpl-classic
all: $(CONTIKI_PROJECT)
MODULES += os/services/simple-energest

MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC
CONTIKI=../..
include $(CONTIKI)/Makefile.include

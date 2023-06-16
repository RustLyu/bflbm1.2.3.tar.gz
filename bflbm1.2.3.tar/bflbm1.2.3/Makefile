ccflags-y := -std=gnu11 -Werror
obj-m += bflbm-drv.o
bflbm-drv-objs := bflbm_decap_ip4.o bflbm_reflect_ip4.o bflbm_decap_ip6.o bflbm_reflect_ip6.o bflbm_init.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
default:
	make -C $(KDIR) SUBDIRS=$(PWD) modules

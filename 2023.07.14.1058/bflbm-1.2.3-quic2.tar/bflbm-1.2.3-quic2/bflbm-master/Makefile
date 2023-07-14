ccflags-y := -std=gnu11 -Werror
obj-m += bflbm-drv.o
bflbm-drv-objs := bflbm_decap_ip4.o bflbm_reflect_ip4.o bflbm_decap_ip6.o bflbm_reflect_ip6.o bflbm_init.o
KDIR := $(shell echo /lib/modules/*/build)
PWD := $(shell pwd)
default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o .*.cmd *.ko .tmp_versions

# obj-m += si917_sdio.o

# CROSS_COMPILER=$(shell readlink -f ../../../99.Toolchain/mips-gcc472-glibc216-64bit/bin)/mips-linux-gnu-
# KERNEL=$(shell readlink -f ../../Zeratul_Release_20220328/os/kernel)

# all:
# 	        make ARCH=mips CROSS_COMPILE=$(CROSS_COMPILER) -C $(KERNEL) M=$(shell pwd) modules

# clean:
# 	        make ARCH=mips CROSS_COMPILE=$(CROSS_COMPILER) -C $(KERNEL) M=$(shell pwd) clean


CROSS_COMPILE ?= mips-linux-gnu-

KDIR := $(PWD)/../../kernel
MODULE_NAME := drv_spi
# MODULE_NAME := irq_gpio

all: modules

.PHONY: modules clean

$(MODULE_NAME)-objs := si917_spi.o
# $(MODULE_NAME)-objs := net_spi.o
obj-m := $(MODULE_NAME).o

modules:
	@$(MAKE) -C $(KDIR) M=$(shell pwd) $@

clean:
	@rm -rf *.o *~ .depend .*.cmd  *.mod.c .tmp_versions *.ko *.symvers modules.order

obj-m += driver/driver.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
TARGET_DIR := target

all: | $(TARGET_DIR)
	rm -rf $(TARGET_DIR)/*
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	gcc -o usermod main.c -Wall -Wextra -O3 -flto -fomit-frame-pointer -msse -msse2 -msse3 -mmmx -m3dnow
	mv *.order *.symvers .*.cmd driver/*.o driver/*.ko driver/*.mod driver/*.mod.c $(TARGET_DIR)
	strip --strip-unneeded $(TARGET_DIR)/driver.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf $(TARGET_DIR)
	rm -rf usermod
	@echo "All the shit is cleaned"

$(TARGET_DIR):
	mkdir -p $(TARGET_DIR)

.PHONY: all clean $(TARGET_DIR)

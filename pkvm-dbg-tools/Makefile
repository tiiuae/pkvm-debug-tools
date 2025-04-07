ifneq ($(KERNELRELEASE),)
clean-files := hyp/hyp.lds hyp/hyp-reloc.S

obj-m := pkvm-dbg-tools.o
pkvm-dbg-tools-y := main.o hyp/kvm_nvhe.o

$(obj)/hyp/kvm_nvhe.o: FORCE
	echo  obj: $(obj)
	$(Q)$(MAKE) $(build)=$(obj)/hyp $(obj)/hyp/kvm_nvhe.o
else
pkvm-dbg-tools:
	make -C $(KERNEL_DIR) ARCH=arm64 M=$(CURDIR) modules

install:
	make -C $(KERNEL_DIR) M=$(CURDIR) INSTALL_MOD_PATH=$(MOD_PATH) modules_install

clean:
	make -C $(KERNEL_DIR) M=$(CURDIR) clean
endif

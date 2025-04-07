
BDIR=root/usr/bin
LDIR=root/usr/lib/aarch64-linux-gnu/
export KERNELRELEASE= $(shell cat $(HOST_KERNEL_DIR)/include/config/kernel.release)
TMPFILE := $(shell mktemp)

LIBS = $(LDIR)/libc.so.6 $(LDIR)/libzstd.so.1 $(LDIR)/ld-linux-aarch64.so.1
LIBS += $(LDIR)/libcrypto.so.3 $(LDIR)/liblzma.so.5

BINS += $(BDIR)/kmod

$(LIBS) : $(LDIR)/% : $(UBUNTU_DIR)/usr/lib/aarch64-linux-gnu/%
	cp  $< $@

$(BINS) : $(BDIR)/% : $(UBUNTU_DIR)/usr/bin/%
	cp  $< $@

root:
	mkdir -p root/usr/bin
	mkdir -p root/usr/lib/aarch64-linux-gnu
	mkdir -p root/lib

cpio_data.cpio: root $(LIBS) $(BINS)
	echo $(TMPFILE)
	./set_kernel_version.py -i cpio_list -o $(TMPFILE) -k $(KERNELRELEASE)
	$(KERNEL_DIR)/usr/gen_init_cpio  $(TMPFILE)   > cpio_data.cpio
	cat cpio_data.cpio | gzip > initramfs.cpio.gz

initramfs : cpio_data.cpio

install:
	cp initramfs.cpio.gz $(OUT_IMAGE)

clean:
	rm -rf root cpio_data.cpio cpio_data.cpio.gz

.PHONY: initramfs root

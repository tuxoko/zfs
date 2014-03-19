FEATURES = $(basename $(wildcard *.c))

JOBS = $(shell grep -c ^processor /proc/cpuinfo)

all:
	$(MAKE) -j$(JOBS) $(FEATURES)

$(FEATURES):
	rm -rf $@.build
	mkdir $@.build
	cp $@.c $@.build
	echo "obj-m = $@.o" > $@.build/Makefile
	-$(MAKE) -C $(LINUX_OBJ) EXTRA_CFLAGS="-Werror $(EXTRA_CFLAGS)" M=$(CURDIR)/$@.build

clean:
	rm -rf $(addsuffix .build,$(FEATURES))

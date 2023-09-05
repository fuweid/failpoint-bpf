obj-m += failpoint-mod.o

build-mod: ## build-mod builds genl module (resolve_btfids)
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean: ## clean clean temp files for module
	@rm -rf *.o *~ core .depend .*.cmd *.mod.c .tmp_versions
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

install-mod: build-mod
	@sudo insmod failpoint-mod.ko

uninstall-mod:
	@sudo rmmod failpoint-mod

.PHONY: help
help: ## help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST) | sort

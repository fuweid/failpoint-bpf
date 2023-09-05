#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/kernel.h>

#define MOD_NAME "FAILPOINT_MOD"

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
                  "Global functions as their definitions will be in vmlinux BTF");

__bpf_kfunc noinline void bpf_failpoint_delay(unsigned int msecs)
{
	msleep(msecs);
}

__diag_pop();

BTF_SET8_START(bpf_failpoint_kfunc_ids)
BTF_ID_FLAGS(func, bpf_failpoint_delay, KF_SLEEPABLE)
BTF_SET8_END(bpf_failpoint_kfunc_ids)

static const struct btf_kfunc_id_set bpf_failpoint_kfunc_set = {
        .owner = THIS_MODULE,
        .set   = &bpf_failpoint_kfunc_ids,
};

static int __init failpointmod_init(void) {
    printk("registering %s module.\n", MOD_NAME);

    return register_btf_kfunc_id_set(BPF_PROG_TYPE_TRACING, &bpf_failpoint_kfunc_set);
}

static void __exit failpointmod_exit(void) {
    printk("unregistered generic %s module.\n", MOD_NAME);
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Wei Fu <fuweid89@gmail.com>");
module_init(failpointmod_init);
module_exit(failpointmod_exit);

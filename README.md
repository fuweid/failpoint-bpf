# failpoint-bpf

## sysfail

The `sysfail` uses bpf to inject failpoint. The `-inject` option format align
with [strace(1)][1]. For example, you can delay [mount(2)][2] with 10 seconds.

```bash
$ sysfail -inject mount:delay_enter=10000:when=1 -pid 1000
```

### install `bpf_failpoint_delay` before run

[bpf-helper(7)][3] doesn't support sleep function. However, fentry/fexit tracing
functions support sleepable call. `sysfail` uses `btf_kfunc` to export kernel
function `msleep` to `bpf_failpoint_delay`. The `btf_kfunc` registration is
done by kernel module

```bash
$ cd bpf/kmod
$ make install-mod
```

### requirement

It requires kernel to build with `CONFIG_FUNCTION_ERROR_INJECTION`.

[1]: <https://man7.org/linux/man-pages/man1/strace.1.html>
[2]: <https://man7.org/linux/man-pages/man2/mount.2.html>
[3]: <https://man7.org/linux/man-pages/man7/bpf-helpers.7.html>

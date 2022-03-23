# TC eBPF example


## command snippets

```bash
# show filters
tc filter show dev eth0 egress
tc filter show dev eth0 ingress

# add filter
tc filter add dev eth0 ingress bpf direct-action obj foo.o sec .text
tc filter add dev eth0 ingress bpf direct-action obj foo.o sec .text

# del filters
tc filter del dev eth0 ingress

# check your debug logs
sudo cat /sys/kernel/debug/tracing/trace_pipe

```


## Links
1. [tc/BPF and XDP/BPF](https://liuhangbin.netlify.app/post/ebpf-and-xdp/)
2. [Error with printk and bpf_trace_printk](https://lists.linuxfoundation.org/pipermail/iovisor-dev/2017-May/000752.html)
3. [bpftool tips](https://twitter.com/qeole/status/1108787801775136768)
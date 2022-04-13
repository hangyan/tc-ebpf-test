#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <stdint.h>
#include <iproute2/bpf_elf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#ifndef __section
# define __section(NAME)                  \
	__attribute__((section(NAME), used))
#endif

#ifndef __inline
# define __inline                         \
        inline __attribute__((always_inline))
#endif

#ifndef lock_xadd
# define lock_xadd(ptr, val)              \
        ((void)__sync_fetch_and_add(ptr, val))
#endif

#ifndef BPF_FUNC
# define BPF_FUNC(NAME, ...)              \
        (*NAME)(__VA_ARGS__) = (void *)BPF_FUNC_##NAME
#endif


#define DEBUG 0
#ifdef  DEBUG
/* Only use this for debug output. Notice output from bpf_trace_printk()
 * end-up in /sys/kernel/debug/tracing/trace_pipe
 */
#define bpf_debug(fmt, ...)						\
		({							\
			char ____fmt[] = fmt;				\
			bpf_trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);			\
		})
#else
#define bpf_debug(fmt, ...) { } while (0)
#endif

static void* BPF_FUNC(map_lookup_elem, void* map, const void* key);

// The number of packets we want to sample and mark.
#define SAMPLES 15


struct bpf_elf_map acc_map __section("maps") = {
    .type = BPF_MAP_TYPE_ARRAY,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint32_t),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 2,

};

// use some hard coded values to reprensents configs
// k --> v
// key=0: sample type
// key=1: FirstNSampleing v: actual packet count. Currently MAX=15
struct bpf_elf_map config_map __section("maps") = {
    .type = BPF_MAP_TYPE_HASH,
    .size_key = sizeof(uint32_t),
    .size_value = sizeof(uint32_t),
    .pinning = PIN_GLOBAL_NS,
    .max_elem = 5,

};

static __inline int account_data(struct __sk_buff *skb, uint32_t dir) {
    uint32_t* bytes;

    uint32_t* count;
    uint32_t count_key = 1;
    count = map_lookup_elem(&config_map, &count_key);

    if (count && *count >= 15){
        return TC_ACT_OK;
    }


    void* data_end = (void*)(long)skb->data_end;
    void* data = (void*)(long)skb->data;
    struct ethhdr* eth = data;
    struct iphdr* iph;

    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return TC_ACT_OK;
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return TC_ACT_OK;
    iph = data + sizeof(*eth);
    __u8 old_tos = iph->tos;
    bpf_debug("got packet id: %u, tos: %u\n", iph->id, old_tos);



    if (count) {
        uint32_t  new_count = *count +1;
        bpf_map_update_elem(&config_map, &count_key, &new_count, BPF_ANY);
    }


    bytes = map_lookup_elem(&acc_map, &dir);
    if (bytes)
        lock_xadd(bytes, skb->len);
    return TC_ACT_OK;
}


__section("ingress")
int tc_ingress(struct __sk_buff* skb)
{
    return account_data(skb, 0);
}

__section("egress")
int tc_egress(struct __sk_buff* skb)
{
    uint32_t  k = 1;
    uint32_t v = 0;
    bpf_map_update_elem(&config_map, &k, &v, BPF_NOEXIST);
    return account_data(skb, 1);
}

char __license[] __section("license") = "GPL";

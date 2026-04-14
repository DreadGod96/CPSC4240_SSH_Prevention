//#include <linux/bpf.h> //eBPF(extended Berkley Packet Filter) subsystem; kernel-mode interaction
#include <linux/if_ether.h> //Layer 2 interactions
#include <linux/ip.h> //Layer 3 interactions
#include <linux/in.h> //IP definitions for byte order conversion

#include <uapi/linux/bpf.h>

//Hash map to store blacklist (map, IPv4 address, timestamp)
BPF_HASH(blacklist, u32, u64);

//xdp-framework for running eBPF to the NIC driver
int xdp_sentinel(struct xdp_md *context) {
    //ptr to the end of the packet buffer
    void *data_end = (void *)(long)context->data_end;
    //ptr to the first byte of the packet arriving to the NIC
    void *data_start = (void *)(long)context->data;

    //Boundary check for layer 2: eBPF verifies its within memory
    //Prevents kernel crash, if packet header doesnt match
    //Read header as ethernet MAC (destination, source, protocol)
    struct ethhdr *ether = data_start;
    //check address after, where IP header begins
    if ((void*)(ether + 1) > data_end) {
        //return safe, proceed to next check
        return XDP_PASS;
    }

    //flip bytes, check if header matches IPv4(ETH_P_IP is default IP header(quick label check))
    //ETH_P_IP -> Standard identifier for IPv4 at layer 2
    if (ether->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    //Boundary Check: Layer 3
    //Validate packet length of an IP Header
    struct iphdr *ipheader = (void*)(ether + 1);
    if ((void*)(ipheader + 1) > data_end) {
        return XDP_PASS;
    }

    //check if IP is in blacklist
     u32 source_ip = ipheader->saddr;
     u64 *value = blacklist.lookup(&source_ip);
    
    //if value is in blacklist, drop packet at NIC driver
    if (value) {
        return XDP_DROP;
    }

    //if not found in blacklist, allow it though the network
    return XDP_PASS;
}





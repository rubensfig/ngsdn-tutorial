/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_ARP  = 0x806;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8> PROTO_ICMP = 1;

#define CPU_PORT 255

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

// packet in 
@controller_header("packet_in")
header packet_in_header_t {
    bit<16>  ingress_port;
    bit<16>  reason;
}

// packet out
@controller_header("packet_out")
header packet_out_header_t {
    bit<16>  egress_port;
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// ARP IP protocol 
header arp_t {
    bit<16>  htype;      // HW type
    bit<16>  ptype;      // Protocol type
    bit<8>  hlen;       // HW addr len
    bit<8>  oper;       // Proto addr len
    bit<16>  opcode;       // Op code
    bit<48> srcMacAddr; // source mac addr
    bit<32> srcIPAddr;  // source IP addr
    bit<48> dstMacAddr; // destination mac addr
    bit<32> dstIPAddr;  // destination IP addr
}

// IPV4 protocol
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header icmp_t {
    bit<8> icmp_type;
    bit<8> icmp_code;
    bit<16> checksum;
    bit<16> identifier;
    bit<16> sequence_number;
    bit<32> gateway;
    bit<48> reserv;
}

struct metadata {
    /* empty */
}

struct headers {
    packet_in_header_t packet_in;
    packet_out_header_t packet_out;
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    arp_t        arp;
    icmp_t        icmp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition select(standard_metadata.ingress_port) {
		CPU_PORT: parse_packet_out;
        	default:  parse_ethernet;
	}
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
          PROTO_ICMP: parse_icmp;
          default: accept;
        }
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action do_send_to_cpu() {
      standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port;
        hdr.packet_in.reason = hdr.ethernet.etherType;
    }
   
    action do_ipv4_send_to_cpu() {
      standard_metadata.egress_spec = CPU_PORT;
        hdr.packet_in.setValid();
        hdr.arp.setInvalid();
        hdr.packet_in.ingress_port = (bit<16>)standard_metadata.ingress_port;
        hdr.packet_in.reason = hdr.ethernet.etherType;
    }

    table send_arp_to_cpu {
      actions = {
        do_send_to_cpu;
      }

      default_action = do_send_to_cpu();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            do_ipv4_send_to_cpu;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = do_ipv4_send_to_cpu();
    }
    
    apply {
        if (hdr.packet_out.isValid()) {
            standard_metadata.egress_spec = (bit<9>)hdr.packet_out.egress_port;
	    hdr.packet_out.setInvalid();
        }
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }

        if (hdr.arp.isValid()) {
            send_arp_to_cpu.apply();
        }

    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply { }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;

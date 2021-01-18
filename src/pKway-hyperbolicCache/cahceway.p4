
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
#define MAX_ENTRIES 16
#define CACHE_SIZE 16
#define ELEMENT_SIZE 48
#define KEY_SIZE 16
#define COUNTER_SIZE 16
#define LOG_REGISTER_SIZE 65536
#define ACCESS_SIZE 16
#define PERIOD_SIZE 16

/*
 * Standard Ethernet header 
 */
header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

/*
 * This is a custom protocol header for the Decision Tree classifier. We'll use 
 * etherType 0x1234 for it (see parser)
 */
const bit<16> P4KWAY_ETYPE = 0x1234;
const bit<8>  P4KWAY_P     = 0x50;   // 'P'
const bit<8>  P4KWAY_4     = 0x34;   // '4'
const bit<8>  P4KWAY_VER   = 0x01;   // v0.1
const bit<8>  P4GET_VAL  = 0x46; // 'F'
const bit<8>  P4UPDATE_LOG  = 0x55; // 'U'

header p4kway_t {
   bit<8>  p;
   bit<8>  four;
   bit<8>  ver;
   bit<8>  type;
   bit<16> k;
   bit<16> v;
   bit<8> cache;
}

/*
 * All headers, used in the program needs to be assembled into a single struct.
 * We only need to declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
struct headers {
    ethernet_t   ethernet;
    p4kway_t     p4kway;
}


/*
 * All metadata, globally used in the program, also  needs to be assembled 
 * into a single struct. As in the case of the headers, we only need to 
 * declare the type, but there is no need to instantiate it,
 * because it is done "by the architecture", i.e. outside of P4 functions
 */
 
struct metadata {
    /* In our case it is empty */
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {    
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            P4KWAY_ETYPE : check_p4kway;
            default      : accept;
        }
    }
    
    state check_p4kway{
        transition select(packet.lookahead<p4kway_t>().p,
        packet.lookahead<p4kway_t>().four,
        packet.lookahead<p4kway_t>().ver) {
            (P4KWAY_P, P4KWAY_4, P4KWAY_VER) : parse_p4kway;
            default                          : accept;
        }
    }
    
    state parse_p4kway {
        packet.extract(hdr.p4kway);
        transition accept;
    }
}

/*************************************************************************
 ************   C H E C K S U M    V E R I F I C A T I O N   *************
 *************************************************************************/
control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
            
    register<bit<(CACHE_SIZE * ELEMENT_SIZE)>>(MAX_ENTRIES) r_cache;
    register<bit<ELEMENT_SIZE>>(MAX_ENTRIES) r_victim_element;
    register<bit<KEY_SIZE>>(MAX_ENTRIES) r_victim_key;
    register<bit<(KEY_SIZE * CACHE_SIZE)>>(MAX_ENTRIES) r_keys;
    bit<(KEY_SIZE * CACHE_SIZE)> keys_mask;
    bit<(KEY_SIZE * CACHE_SIZE)> keys_bit;

    register<bit<COUNTER_SIZE>>(1) r_conf;
    register<bit<PERIOD_SIZE>>(LOG_REGISTER_SIZE) r_log;

    action send_back() {
       bit<48> tmp;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action get_element_from_cache(in bit<32> h, in bit<32> index) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<(ELEMENT_SIZE * CACHE_SIZE)> element;

        r_cache.read(element, h);
        
bit<ELEMENT_SIZE> element0 = element[47:0];
if (index == 0) {
    if (element0[47:32] == requested_key) {
        element0[31:16] = element0[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element1 = element[95:48];
if (index == 1) {
    if (element1[47:32] == requested_key) {
        element1[31:16] = element1[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element2 = element[143:96];
if (index == 2) {
    if (element2[47:32] == requested_key) {
        element2[31:16] = element2[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element3 = element[191:144];
if (index == 3) {
    if (element3[47:32] == requested_key) {
        element3[31:16] = element3[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element4 = element[239:192];
if (index == 4) {
    if (element4[47:32] == requested_key) {
        element4[31:16] = element4[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element5 = element[287:240];
if (index == 5) {
    if (element5[47:32] == requested_key) {
        element5[31:16] = element5[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element6 = element[335:288];
if (index == 6) {
    if (element6[47:32] == requested_key) {
        element6[31:16] = element6[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element7 = element[383:336];
if (index == 7) {
    if (element7[47:32] == requested_key) {
        element7[31:16] = element7[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element8 = element[431:384];
if (index == 8) {
    if (element8[47:32] == requested_key) {
        element8[31:16] = element8[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element9 = element[479:432];
if (index == 9) {
    if (element9[47:32] == requested_key) {
        element9[31:16] = element9[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element10 = element[527:480];
if (index == 10) {
    if (element10[47:32] == requested_key) {
        element10[31:16] = element10[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element11 = element[575:528];
if (index == 11) {
    if (element11[47:32] == requested_key) {
        element11[31:16] = element11[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element12 = element[623:576];
if (index == 12) {
    if (element12[47:32] == requested_key) {
        element12[31:16] = element12[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element13 = element[671:624];
if (index == 13) {
    if (element13[47:32] == requested_key) {
        element13[31:16] = element13[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element14 = element[719:672];
if (index == 14) {
    if (element14[47:32] == requested_key) {
        element14[31:16] = element14[31:16] + 1;
    }
}

bit<ELEMENT_SIZE> element15 = element[767:720];
if (index == 15) {
    if (element15[47:32] == requested_key) {
        element15[31:16] = element15[31:16] + 1;
    }
}

        element = element15 ++ element14 ++ element13 ++ element12 ++ element11 ++ element10 ++ element9 ++ element8 ++ element7 ++ element6 ++ element5 ++ element4 ++ element3 ++ element2 ++ element1 ++ element0;
        r_cache.write(h, element);
    }

    action insert_key_to_keys_register(in bit<32> h, in bit<32> index, in bit<KEY_SIZE> key_to_insert, out bit<KEY_SIZE> new_victim_key) {
        new_victim_key = 0;
        bit<(KEY_SIZE * CACHE_SIZE)> keys;
        r_keys.read(keys, h);
        
bit<16> key0 = keys[15:0];
if (index == 0) {
    new_victim_key = key0;
    key0 = key_to_insert;
} 

bit<16> key1 = keys[31:16];
if (index == 1) {
    new_victim_key = key1;
    key1 = key_to_insert;
} 

bit<16> key2 = keys[47:32];
if (index == 2) {
    new_victim_key = key2;
    key2 = key_to_insert;
} 

bit<16> key3 = keys[63:48];
if (index == 3) {
    new_victim_key = key3;
    key3 = key_to_insert;
} 

bit<16> key4 = keys[79:64];
if (index == 4) {
    new_victim_key = key4;
    key4 = key_to_insert;
} 

bit<16> key5 = keys[95:80];
if (index == 5) {
    new_victim_key = key5;
    key5 = key_to_insert;
} 

bit<16> key6 = keys[111:96];
if (index == 6) {
    new_victim_key = key6;
    key6 = key_to_insert;
} 

bit<16> key7 = keys[127:112];
if (index == 7) {
    new_victim_key = key7;
    key7 = key_to_insert;
} 

bit<16> key8 = keys[143:128];
if (index == 8) {
    new_victim_key = key8;
    key8 = key_to_insert;
} 

bit<16> key9 = keys[159:144];
if (index == 9) {
    new_victim_key = key9;
    key9 = key_to_insert;
} 

bit<16> key10 = keys[175:160];
if (index == 10) {
    new_victim_key = key10;
    key10 = key_to_insert;
} 

bit<16> key11 = keys[191:176];
if (index == 11) {
    new_victim_key = key11;
    key11 = key_to_insert;
} 

bit<16> key12 = keys[207:192];
if (index == 12) {
    new_victim_key = key12;
    key12 = key_to_insert;
} 

bit<16> key13 = keys[223:208];
if (index == 13) {
    new_victim_key = key13;
    key13 = key_to_insert;
} 

bit<16> key14 = keys[239:224];
if (index == 14) {
    new_victim_key = key14;
    key14 = key_to_insert;
} 

bit<16> key15 = keys[255:240];
if (index == 15) {
    new_victim_key = key15;
    key15 = key_to_insert;
} 
        keys = key15 ++ key14 ++ key13 ++ key12 ++ key11 ++ key10 ++ key9 ++ key8 ++ key7 ++ key6 ++ key5 ++ key4 ++ key3 ++ key2 ++ key1 ++ key0;
        r_keys.write(h, keys);
    }

    action insert_to_cache_inner(in bit<32> index, in bit<KEY_SIZE> k, in bit<COUNTER_SIZE> scn, in bit<ACCESS_SIZE> access, inout bit<ELEMENT_SIZE> element) {
        bit<ELEMENT_SIZE> victim_element = 0;
        victim_element[47:32] = element[47:32];
        victim_element[31:16] = element[31:16];
        victim_element[15:0] = element[15:0];
        r_victim_element.write(0, victim_element);

        element[47:32] = k;
        element[31:16] = access;
        element[15:0] = scn;
    }

    action insert_to_cache(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element, in bit<COUNTER_SIZE> scn) {
        bit<ELEMENT_SIZE> current_victim;
        r_victim_element.read(current_victim, 0);

        insert_to_cache_inner(index, current_victim[47:32], scn,current_victim[31:16], element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> current_victim_key;
        r_victim_key.read(current_victim_key, 0);

        bit<KEY_SIZE> next_victim_key;
        insert_key_to_keys_register(h, index, current_victim_key, next_victim_key);
        r_victim_key.write(0, next_victim_key);
    }

    action insert_to_cache_first_element(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element, in bit<COUNTER_SIZE> scn) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;

        insert_to_cache_inner(index, requested_key, scn, 1, element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> next_victim;
        insert_key_to_keys_register(h, index, hdr.p4kway.k, next_victim);
        r_victim_key.write(0, next_victim);
    }

    action get_hyperbolic_cache_pr(in bit<ACCESS_SIZE> number_of_access, in bit<COUNTER_SIZE> period, out bit<PERIOD_SIZE> pr){
        bit<PERIOD_SIZE> number_of_access_log;
        bit<PERIOD_SIZE> period_log;

         r_log.read(number_of_access_log, (bit<32>)number_of_access);
         r_log.read(period_log, (bit<32>)period);

         pr = number_of_access_log - period_log;
    }

    action operation_drop() {
        mark_to_drop(standard_metadata);
    }

    action operation_update_log() {
        r_log.write((bit<32>)hdr.p4kway.k, hdr.p4kway.v);
    }

    action mark_hit() {
	    hdr.p4kway.cache = 1;
    }

    action mark_miss() {
	    hdr.p4kway.cache = 0;
    }

    table check_cache {
        key = {
	        keys_mask: ternary;
        }
        actions = {
		    mark_hit;
		    mark_miss;
        }
        const default_action = mark_miss();
        const entries = {
	        256w0x0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 256w0xFFFF000000000000000000000000000000000000000000000000000000000000: mark_hit();
256w0xFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 256w0x0000FFFF00000000000000000000000000000000000000000000000000000000: mark_hit();
256w0xFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 256w0x00000000FFFF0000000000000000000000000000000000000000000000000000: mark_hit();
256w0xFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 256w0x000000000000FFFF000000000000000000000000000000000000000000000000: mark_hit();
256w0xFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 256w0x0000000000000000FFFF00000000000000000000000000000000000000000000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 256w0x00000000000000000000FFFF0000000000000000000000000000000000000000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 256w0x000000000000000000000000FFFF000000000000000000000000000000000000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 256w0x0000000000000000000000000000FFFF00000000000000000000000000000000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 256w0x00000000000000000000000000000000FFFF0000000000000000000000000000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFF &&& 256w0x000000000000000000000000000000000000FFFF000000000000000000000000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFF &&& 256w0x0000000000000000000000000000000000000000FFFF00000000000000000000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFF &&& 256w0x00000000000000000000000000000000000000000000FFFF0000000000000000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFF &&& 256w0x000000000000000000000000000000000000000000000000FFFF000000000000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFF &&& 256w0x0000000000000000000000000000000000000000000000000000FFFF00000000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFF &&& 256w0x00000000000000000000000000000000000000000000000000000000FFFF0000: mark_hit();
256w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000 &&& 256w0x000000000000000000000000000000000000000000000000000000000000FFFF: mark_hit();
        }
    }

    action skip() { 
        // Do nothing
    }

    table noop_key {
        key = {
	        hdr.p4kway.k: exact;
        }
        actions = {
		    skip;
        }
        const default_action = skip();
    }

    table noop_value {
        key = {
	        hdr.p4kway.v: exact;
        }
        actions = {
		    skip;
        }
        const default_action = skip();
    }

    apply {
        if (hdr.p4kway.isValid()) {
            if (hdr.p4kway.type == P4UPDATE_LOG) {
                noop_key.apply();
                noop_value.apply();
                operation_update_log();
            }
            else {
                bit<32> h = (bit<32>)hdr.p4kway.k % MAX_ENTRIES;
                r_keys.read(keys_bit, h);
                keys_mask = (hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k) ^ keys_bit;

                bit<COUNTER_SIZE> scn;
                r_conf.read(scn, 0);
                scn = scn + 1;
                r_conf.write(0, scn);

                check_cache.apply();

                if (hdr.p4kway.cache == 1) {
                    get_element_from_cache(h ,0);
get_element_from_cache(h ,1);
get_element_from_cache(h ,2);
get_element_from_cache(h ,3);
get_element_from_cache(h ,4);
get_element_from_cache(h ,5);
get_element_from_cache(h ,6);
get_element_from_cache(h ,7);
get_element_from_cache(h ,8);
get_element_from_cache(h ,9);
get_element_from_cache(h ,10);
get_element_from_cache(h ,11);
get_element_from_cache(h ,12);
get_element_from_cache(h ,13);
get_element_from_cache(h ,14);
get_element_from_cache(h ,15);
                } else {
                    bit<ELEMENT_SIZE> current_victim = 0;
                    bit<KEY_SIZE> victim_key = 0;
                    bit<(ELEMENT_SIZE * CACHE_SIZE)> element;
                    r_cache.read(element, h);

                    bit<ELEMENT_SIZE> element0 = element[47:0];
                    insert_to_cache_first_element(h, 0, element0, scn);
                    bit<PERIOD_SIZE> pr_1;
                    bit<PERIOD_SIZE> pr_2;
                    
bit<ELEMENT_SIZE> element1 = element[95:48];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element1[31:16], (scn - element1[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 1, element1, scn);
}

bit<ELEMENT_SIZE> element2 = element[143:96];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element2[31:16], (scn - element2[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 2, element2, scn);
}

bit<ELEMENT_SIZE> element3 = element[191:144];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element3[31:16], (scn - element3[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 3, element3, scn);
}

bit<ELEMENT_SIZE> element4 = element[239:192];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element4[31:16], (scn - element4[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 4, element4, scn);
}

bit<ELEMENT_SIZE> element5 = element[287:240];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element5[31:16], (scn - element5[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 5, element5, scn);
}

bit<ELEMENT_SIZE> element6 = element[335:288];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element6[31:16], (scn - element6[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 6, element6, scn);
}

bit<ELEMENT_SIZE> element7 = element[383:336];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element7[31:16], (scn - element7[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 7, element7, scn);
}

bit<ELEMENT_SIZE> element8 = element[431:384];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element8[31:16], (scn - element8[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 8, element8, scn);
}

bit<ELEMENT_SIZE> element9 = element[479:432];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element9[31:16], (scn - element9[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 9, element9, scn);
}

bit<ELEMENT_SIZE> element10 = element[527:480];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element10[31:16], (scn - element10[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 10, element10, scn);
}

bit<ELEMENT_SIZE> element11 = element[575:528];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element11[31:16], (scn - element11[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 11, element11, scn);
}

bit<ELEMENT_SIZE> element12 = element[623:576];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element12[31:16], (scn - element12[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 12, element12, scn);
}

bit<ELEMENT_SIZE> element13 = element[671:624];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element13[31:16], (scn - element13[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 13, element13, scn);
}

bit<ELEMENT_SIZE> element14 = element[719:672];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element14[31:16], (scn - element14[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 14, element14, scn);
}

bit<ELEMENT_SIZE> element15 = element[767:720];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element15[31:16], (scn - element15[15:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[31:16], (scn - current_victim[15:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, 15, element15, scn);
}

                    element = element15 ++ element14 ++ element13 ++ element12 ++ element11 ++ element10 ++ element9 ++ element8 ++ element7 ++ element6 ++ element5 ++ element4 ++ element3 ++ element2 ++ element1 ++ element0;
                    r_cache.write(h, element);
                }
                send_back();
            }
        } else {
            operation_drop();
        }
    }
}

/************************************************************
 ****************  REGISTER DEFINITIONS   *******************
 ************************************************************/



/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
 *************   C H E C K S U M    C O M P U T A T I O N   **************
 *************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
 ***********************  D E P A R S E R  *******************************
 *************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.p4kway);
    }
}

/*************************************************************************
 ***********************  S W I T T C H **********************************
 *************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
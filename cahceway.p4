
#include <core.p4>
#include <v1model.p4>

#define MAX_ENTRIES 1
#define MAIN_CACHE_SIZE 4
#define FRONT_CACHE_SIZE 2
#define ELEMENT_SIZE 32
#define KEY_SIZE 8

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

const bit<16> P4KWAY_ETYPE = 0x1234;
const bit<8>  P4KWAY_P     = 0x50;   // 'P'
const bit<8>  P4KWAY_4     = 0x34;   // '4'
const bit<8>  P4KWAY_VER   = 0x01;   // v0.1
const bit<8>  P4GET_VAL_LFU  = 0x46;   // 'F'
const bit<8>  P4GET_VAL_FIFO  = 0x52;   // 'R'

header p4kway_t {
   bit<8>  p;
   bit<8>  four;
   bit<8>  ver;
   bit<8>  type;
   bit<8> k;
   bit<16> v;
   bit<8> cache;
   bit<8> front;
}

struct headers {
    ethernet_t   ethernet;
    p4kway_t     p4kway;
}

struct metadata {
    /* In our case it is empty */
}

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

control MyVerifyChecksum(inout headers hdr,
                         inout metadata meta) {
    apply { }
}

bit<16> load(in bit<8> k) {
    return (bit<16>)(k * k);
}

bit<8> max(in bit<8> scn1, in bit<8> scn2) {
    if (scn1 >= scn2){
        return scn1;
    }
    else{
        return scn2;
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    // Elements cache
    register<bit<(ELEMENT_SIZE * MAIN_CACHE_SIZE)>>(MAX_ENTRIES) r_main_cache;  // MAX_ENTRIES Elements. Each element is 32 bit.
    register<bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)>>(MAX_ENTRIES) r_front_cache;

    // Victim element. Common for the two caches.
    register<bit<ELEMENT_SIZE>>(MAX_ENTRIES) r_victim_element;

    // Keys cache
    register<bit<(KEY_SIZE * MAIN_CACHE_SIZE)>>(MAX_ENTRIES) r_main_keys;
    register<bit<(KEY_SIZE * FRONT_CACHE_SIZE)>>(MAX_ENTRIES) r_front_keys;
    
    // Victim Key. Common for thw two cached
    register<bit<KEY_SIZE>>(MAX_ENTRIES) r_victim_key; 
    
    // Masks to check whether or not the requested key is in the cache
    bit<(KEY_SIZE * MAIN_CACHE_SIZE)> main_keys_mask;
    bit<(KEY_SIZE * FRONT_CACHE_SIZE)> front_keys_mask;
    
    // Bit that represent the keys in the cache
    bit<(KEY_SIZE * FRONT_CACHE_SIZE)> front_keys_bit;
    bit<(KEY_SIZE * MAIN_CACHE_SIZE)> main_keys_bit;

    
    action send_back() {
       bit<48> tmp;

        /* Swap the MAC addresses */
        tmp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = tmp;

        /* Send the packet back to the port it came from */
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    action insert_key_to_front_keys_register(in bit<32> h, in bit<32> index, in bit<KEY_SIZE> key_to_insert, out bit<KEY_SIZE> new_victim_key) {
        bit<(KEY_SIZE * FRONT_CACHE_SIZE)> keys;
        r_front_keys.read(keys, h);
        if (index == 0) {
            new_victim_key = keys[7:0];
            keys[7:0] = key_to_insert;
        } else if (index == 1) {
            new_victim_key = keys[15:8];
            keys[15:8] = key_to_insert;
        }
        r_front_keys.write(h, keys);
    }

    action insert_key_to_main_keys_register(in bit<32> h, in bit<32> index, in bit<KEY_SIZE> key_to_insert, out bit<KEY_SIZE> new_victim_key) {
        bit<(KEY_SIZE * MAIN_CACHE_SIZE)> keys;
        r_main_keys.read(keys, h);
        if (index == 0) {
            new_victim_key = keys[7:0];
            keys[7:0] = key_to_insert;
        } else if (index == 1) {
            new_victim_key = keys[15:8];
            keys[15:8] = key_to_insert;
        } else if (index == 2) {
            new_victim_key = keys[23:16];
            keys[23:16] = key_to_insert;
        } else if (index == 3) {
            new_victim_key = keys[31:24];
            keys[31:24] = key_to_insert;
        }
        r_main_keys.write(h, keys);
    }

    action get_element_from_main_cache_with_lfu(in bit<32> h, in bit<32> index) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<(ELEMENT_SIZE * MAIN_CACHE_SIZE)> element;

        r_main_cache.read(element, h);
       bit<ELEMENT_SIZE> element0 = element[31:0];
       bit<ELEMENT_SIZE> element1 = element[63:32];
       bit<ELEMENT_SIZE> element2 = element[95:64];
       bit<ELEMENT_SIZE> element3 = element[127:96];

        if (index == 0) {
            if (element0[31:24] == requested_key) {
                hdr.p4kway.v = element0[23:8];
                element0[7:0] = element0[7:0] + 1;
            }

        } else if (index == 1) {
            if (element1[31:24] == requested_key) {
                hdr.p4kway.v = element1[23:8];
                element1[7:0] = element1[7:0] + 1;
            }

        } else if (index == 2) {
            if (element2[31:24] == requested_key) {
                hdr.p4kway.v = element2[23:8];
                element2[7:0] = element2[7:0] + 1;
            }

        } else if (index == 3) {
            if (element3[31:24] == requested_key) {
                hdr.p4kway.v = element3[23:8];
                element3[7:0] = element3[7:0] + 1;
            }

        }

        element = element3 ++ element2 ++ element1 ++ element0;
        r_main_cache.write(h, element);
    }

    action get_element_from_front_cache_with_lfu(in bit<32> h, in bit<32> index) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> element;

        r_front_cache.read(element, h);
        bit<ELEMENT_SIZE> element1 = element[63:32];
        bit<ELEMENT_SIZE> element0 = element[31:0];

        if (index == 0) {
            if (element0[31:24] == requested_key) {
                hdr.p4kway.v = element0[23:8];
                element0[7:0] = element0[7:0] + 1;
            }

        } else if (index == 1) {
            if (element1[31:24] == requested_key) {
                hdr.p4kway.v = element1[23:8];
                element1[7:0] = element1[7:0] + 1;
            }

        }

        element = element1 ++ element0;
        r_front_cache.write(h, element);
    }

    action insert_to_lfu_inner(in bit<32> index, in bit<KEY_SIZE> k, in bit<16> v, in bit<8> c, inout bit<32> element) {
        bit<ELEMENT_SIZE> victim_element = 0;
        victim_element[31:24] = element[31:24];
        victim_element[23:8] = element[23:8];
        victim_element[7:0] = element[7:0];
        if (victim_element[7:0] > 0) {
            victim_element[7:0] = victim_element[7:0] - 1;
        }
        r_victim_element.write(0, victim_element);

         // Update cache[0] to be the new element 
        element[31:24] = k;
        element[23:8] = v;
        element[7:0] = c;
    }

    action insert_to_main_cache_with_lfu_first_element(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<16> loaded_val = load(requested_key);

        insert_to_lfu_inner(index, requested_key, loaded_val, 1, element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> next_victim;
        insert_key_to_main_keys_register(h, index, hdr.p4kway.k, next_victim);
        r_victim_key.write(0, next_victim);
    }

    action insert_to_front_cache_with_lfu_first_element(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<16> loaded_val = load(requested_key);

        insert_to_lfu_inner(index, requested_key, loaded_val, 1, element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> next_victim;
        insert_key_to_front_keys_register(h, index, hdr.p4kway.k, next_victim);
        r_victim_key.write(0, next_victim);
    }

    action insert_to_main_cache_with_lfu(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element) {
        bit<ELEMENT_SIZE> current_victim;
        r_victim_element.read(current_victim, 0);

        insert_to_lfu_inner(index, current_victim[31:24], current_victim[23:8], current_victim[7:0], element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> current_victim_key;
        r_victim_key.read(current_victim_key, 0);

        bit<KEY_SIZE> next_victim_key;
        insert_key_to_main_keys_register(h, index, current_victim_key, next_victim_key);
        r_victim_key.write(0, next_victim_key);
    }

    action insert_to_front_cache_with_lfu(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element) {
        bit<ELEMENT_SIZE> current_victim;
        r_victim_element.read(current_victim, 0);

        insert_to_lfu_inner(index, current_victim[31:24], current_victim[23:8], current_victim[7:0], element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> current_victim_key;
        r_victim_key.read(current_victim_key, 0);

        bit<KEY_SIZE> next_victim_key;
        insert_key_to_front_keys_register(h, index, current_victim_key, next_victim_key);
        r_victim_key.write(0, next_victim_key);
    }

    action operation_drop() {
        mark_to_drop(standard_metadata);
    }

    action mark_main_hit() {
	    hdr.p4kway.cache = 1;
    }

    action mark_front_hit() {
	    hdr.p4kway.front = 1;
    }

    action mark_main_miss() {
	    hdr.p4kway.cache = 0;
    }

    action mark_front_miss() {
	    hdr.p4kway.front = 0;
    }

    action skip() { 
        // Do nothing
    }

    table check_main_cache {
        key = {
	        main_keys_mask: ternary;
        }
        actions = {
		    mark_main_hit;
		    mark_main_miss;
        }
        const default_action = mark_main_miss();
        const entries = {
	        32w0x00FFFFFF &&& 32w0xFF000000: mark_main_hit();
	        32w0xFF00FFFF &&& 32w0x00FF0000: mark_main_hit();
	        32w0xFFFF00FF &&& 32w0x0000FF00: mark_main_hit();
	        32w0xFFFFFF00 &&& 32w0x000000FF: mark_main_hit();
        }
    }

    table check_front_cache {
        key = {
	        front_keys_mask: ternary;
        }
        actions = {
		    mark_front_hit;
		    mark_front_miss;
        }
        const default_action = mark_front_miss();
        const entries = {
	        16w0x00FF &&& 16w0xFF00: mark_front_hit();
	        16w0xFF00 &&& 16w0x00FF: mark_front_hit();
        }
    }

    apply {
        if (hdr.p4kway.isValid()) {
            bit<32> h = (bit<32>) (hdr.p4kway.k % MAX_ENTRIES);
            r_front_keys.read(front_keys_bit, h);
            r_main_keys.read(main_keys_bit, h);
            front_keys_mask = (hdr.p4kway.k ++ hdr.p4kway.k) ^ front_keys_bit;
            main_keys_mask = (hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k) ^ main_keys_bit;

            check_main_cache.apply();
            check_front_cache.apply();
            
            if (hdr.p4kway.cache == 1) {
                // Retrieve from main cache
                get_element_from_main_cache_with_lfu(h ,0);
                get_element_from_main_cache_with_lfu(h ,1);
                get_element_from_main_cache_with_lfu(h ,2);
                get_element_from_main_cache_with_lfu(h ,3);

            } else if (hdr.p4kway.front == 1) {
                // Retrieve from front cache
                get_element_from_front_cache_with_lfu(h ,0);
                get_element_from_front_cache_with_lfu(h, 1);

            } else {
                bit<ELEMENT_SIZE> current_victim = 0;

                // Insert to front cache
                bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> front_cache_element;
                r_front_cache.read(front_cache_element, h);

                bit<ELEMENT_SIZE> front_element_0 = front_cache_element[31:0];
                insert_to_front_cache_with_lfu_first_element(h, 0, front_element_0);

                bit<ELEMENT_SIZE> front_element_1 = front_cache_element[63:32];
                r_victim_element.read(current_victim, 0);
                if (hdr.p4kway.type == P4GET_VAL_LFU && front_element_1[7:0] > current_victim[7:0]) {
                    if (front_element_1[7:0] > 0) {
                        front_element_1[7:0] = front_element_1[7:0] - 1;
                    }
                } else {
                    insert_to_front_cache_with_lfu(h, 1, front_element_1);
                }

                front_cache_element = front_element_1 ++ front_element_0;
                r_front_cache.write(h, front_cache_element);

                r_victim_element.read(current_victim, 0);
                if (current_victim[31:24] != 0) {
                    bit<(ELEMENT_SIZE * MAIN_CACHE_SIZE)> element;
                    r_main_cache.read(element, h);     
                    
                    bit<ELEMENT_SIZE> element0 = element[31:0];
                    r_victim_element.read(current_victim, 0);
                    if (hdr.p4kway.type == P4GET_VAL_LFU && element0[7:0] > current_victim[7:0]) {
                        if (element0[7:0] > 0) {
                            element0[7:0] = element0[7:0] - 1;
                        }
                    } else {
                        insert_to_main_cache_with_lfu(h, 0, element0);
                    }

                    bit<ELEMENT_SIZE> element1 = element[63:32];
                    r_victim_element.read(current_victim, 0);
                    if (hdr.p4kway.type == P4GET_VAL_LFU && element1[7:0] > current_victim[7:0]) {
                        if (element1[7:0] > 0) {
                            element1[7:0] = element1[7:0] - 1;
                        }
                    } else {
                        insert_to_main_cache_with_lfu(h, 1, element1);
                    }

                    bit<ELEMENT_SIZE> element2 = element[95:64];
                    r_victim_element.read(current_victim, 0);
                    if (hdr.p4kway.type == P4GET_VAL_LFU && element2[7:0] > current_victim[7:0]) {
                        if (element2[7:0] > 0) {
                            element2[7:0] = element2[7:0] - 1;
                        }
                    } else {
                        insert_to_main_cache_with_lfu(h, 2, element2);
                    }

                    bit<ELEMENT_SIZE> element3 = element[127:96];
                    r_victim_element.read(current_victim, 0);
                    if (hdr.p4kway.type == P4GET_VAL_LFU && element3[7:0] > current_victim[7:0]) {
                        if (element3[7:0] > 0) {
                            element3[7:0] = element3[7:0] - 1;
                        }
                    } else {
                        insert_to_main_cache_with_lfu(h, 3, element3);
                    }

                    element = element3 ++ element2 ++ element1 ++ element0;
                    r_main_cache.write(h, element);
                }    
            }
            send_back();
        } else {
            operation_drop();
        }
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.p4kway);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
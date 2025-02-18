
#include <core.p4>
#include <v1model.p4>

#define MAX_ENTRIES 1
#define MAIN_CACHE_SIZE 2
#define FRONT_CACHE_SIZE 1
#define ELEMENT_SIZE 80
#define KEY_SIZE 16
#define COUNTER_SIZE 32

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
const bit<8>  P4GET_VAL_LRU  = 0x52;   // 'R'
const bit<8>  P4GET_VAL_FIFO  = 0x4F;   // 'O'

header p4kway_t {
   bit<8>  p;
   bit<8>  four;
   bit<8>  ver;
   bit<8>  front_type;
   bit<8>  main_type;
   bit<16> k;
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

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<(COUNTER_SIZE)>>(65535) r_counter;
    register<bit<32>>(1) r_timestamp;

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
        new_victim_key = 0;
        bit<(KEY_SIZE * FRONT_CACHE_SIZE)> keys;
        r_front_keys.read(keys, h);
        
bit<16> key0 = keys[15:0];
if (index == 0) {
    new_victim_key = key0;
    key0 = key_to_insert;
} 
        keys = key0;
        r_front_keys.write(h, keys);
    }

    action insert_key_to_main_keys_register(in bit<32> h, in bit<32> index, in bit<KEY_SIZE> key_to_insert, out bit<KEY_SIZE> new_victim_key) {
        new_victim_key = 0;
        bit<(KEY_SIZE * MAIN_CACHE_SIZE)> keys;
        r_main_keys.read(keys, h);
        
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
        keys = key1 ++ key0;
        r_main_keys.write(h, keys);
    }

    action get_element_from_main_cache(in bit<32> h, in bit<32> index, in bit<32> timestamp) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<(ELEMENT_SIZE * MAIN_CACHE_SIZE)> main_element;

        r_main_cache.read(main_element, h);
        
bit<ELEMENT_SIZE> main_element0 = main_element[79:0];
if (index == 0) {
    if (main_element0[79:64] == requested_key) {
        main_element0[31:0] = main_element0[31:0] + 1; // LFU
        main_element0[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> main_element1 = main_element[159:80];
if (index == 1) {
    if (main_element1[79:64] == requested_key) {
        main_element1[31:0] = main_element1[31:0] + 1; // LFU
        main_element1[63:32] = timestamp; //LRU
    }
}

        main_element = main_element1 ++ main_element0;
        r_main_cache.write(h, main_element);
    }

    action get_element_from_front_cache(in bit<32> h, in bit<32> index, in bit<32> timestamp) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> front_element;

        r_front_cache.read(front_element, h);
        
bit<ELEMENT_SIZE> front_element0 = front_element[79:0];
if (index == 0) {
    if (front_element0[79:64] == requested_key) {
        front_element0[31:0] = front_element0[31:0] + 1; // LFU
        front_element0[63:32] = timestamp; //LRU
    }
}

        front_element = front_element0;
        r_front_cache.write(h, front_element);
    }

    action insert_to_cache_inner(in bit<32> index, in bit<KEY_SIZE> k, in bit<32> c, in bit<32> timestamp, inout bit<ELEMENT_SIZE> element) {
        bit<ELEMENT_SIZE> victim_element = 0;
        victim_element[79:64] = element[79:64]; //k
        victim_element[31:0] = element[31:0];   //LFU
        victim_element[63:32] = element[63:32];   //LRU
        //if (victim_element[31:0] > 0) {
        //    victim_element[31:0] = victim_element[31:0] - 1;
        //}
        r_victim_element.write(0, victim_element);

         // Update cache[0] to be the new element 
        element[79:64] = k;
        element[63:32] = timestamp; // LRU
        element[31:0] = c; //LFU
    }

    action insert_to_main_cache_first_element(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element, in bit<32> timestamp) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;

        insert_to_cache_inner(index, requested_key, 1, timestamp, element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> next_victim;
        insert_key_to_main_keys_register(h, index, hdr.p4kway.k, next_victim);
        r_victim_key.write(0, next_victim);
    }

    action insert_to_front_cache_first_element(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element, in bit<32> timestamp) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;

        insert_to_cache_inner(index, requested_key, 1, timestamp, element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> next_victim;
        insert_key_to_front_keys_register(h, index, hdr.p4kway.k, next_victim);
        r_victim_key.write(0, next_victim);
    }

    action insert_to_main_cache(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element, in bit<32> timestamp) {
        bit<ELEMENT_SIZE> current_victim;
        r_victim_element.read(current_victim, 0);
        
        insert_to_cache_inner(index, current_victim[79:64], current_victim[31:0], timestamp, element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> current_victim_key;
        r_victim_key.read(current_victim_key, 0);

        bit<KEY_SIZE> next_victim_key;
        insert_key_to_main_keys_register(h, index, current_victim_key, next_victim_key);
        r_victim_key.write(0, next_victim_key);
    }

    action insert_to_front_cache(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element, in bit<32> timestamp) {
        bit<ELEMENT_SIZE> current_victim;
        r_victim_element.read(current_victim, 0);

        insert_to_cache_inner(index, current_victim[79:64], current_victim[31:0], timestamp, element);

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
	        32w0x0000FFFF &&& 32w0xFFFF0000: mark_main_hit();
32w0xFFFF0000 &&& 32w0x0000FFFF: mark_main_hit();
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
	        16w0x0000 &&& 16w0xFFFF: mark_front_hit();
        }
    }

    table noop_front {
        key = {
	        front_keys_bit: exact;
        }
        actions = {
		    skip;
        }
        const default_action = skip();
    }

    table noop_main {
        key = {
	        main_keys_bit: exact;
        }
        actions = {
		    skip;
        }
        const default_action = skip();
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

    apply {
        if (hdr.p4kway.isValid()) {

            //Deamorization Process:
            bit<COUNTER_SIZE> counter_value;
            bit<COUNTER_SIZE> current_timestamp;
            r_timestamp.read(current_timestamp, 0);
            
            current_timestamp = current_timestamp + 1;
            r_timestamp.write(0, current_timestamp);
            
            r_counter.read(counter_value, (bit<32>)hdr.p4kway.k);
            counter_value = counter_value + 1;
            r_counter.write((bit<32>)hdr.p4kway.k, counter_value);
            

            bit<32> h = (bit<32>)hdr.p4kway.k % MAX_ENTRIES;
            r_front_keys.read(front_keys_bit, h);
            r_main_keys.read(main_keys_bit, h);
            front_keys_mask = (hdr.p4kway.k) ^ front_keys_bit;
            main_keys_mask = (hdr.p4kway.k ++ hdr.p4kway.k) ^ main_keys_bit;

            check_main_cache.apply();
            check_front_cache.apply();
            noop_main.apply();
            noop_front.apply();
            noop_key.apply();

            
            if (hdr.p4kway.cache == 1) {
                // Retrieve from main cache
                get_element_from_main_cache(h ,0, current_timestamp);
get_element_from_main_cache(h ,1, current_timestamp);

            } else if (hdr.p4kway.front == 1) {
                // Retrieve from front cache
                get_element_from_front_cache(h ,0, current_timestamp);

            } else {
                bit<ELEMENT_SIZE> current_victim = 0;
                bit<KEY_SIZE> victim_key = 0;
                bool insert = true;

                // Insert to front cache
                bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> front_element;
                r_front_cache.read(front_element, h);

                bit<ELEMENT_SIZE> front_element0 = front_element[79:0];
                insert_to_front_cache_first_element(h, 0, front_element0, current_timestamp);

                

                front_element = front_element0;
                r_front_cache.write(h, front_element);

                r_victim_key.read(victim_key, 0);
                if (victim_key != 0) {
                    bit<(ELEMENT_SIZE * MAIN_CACHE_SIZE)> main_element;
                    r_main_cache.read(main_element, h);   
                    bit<ELEMENT_SIZE> main_element0 = main_element[79:0];
                    r_victim_element.read(current_victim, 0);
                    //if (main_element0[31:0] > 0) {
                    //   main_element0[31:0] = main_element0[31:0] - 1;
                    //}
                    insert_to_main_cache(h, 0, main_element0, current_timestamp); 
                    
bit<ELEMENT_SIZE> main_element1 = main_element[159:80];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.main_type == P4GET_VAL_LFU && main_element1[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.main_type == P4GET_VAL_LRU && main_element1[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_main_cache(h, 1, main_element1, current_timestamp);
    } else {
        //if (main_element1[31:0] > 0) {
        //    main_element1[31:0] = main_element1[31:0] - 1;
        //}
    }
}

                    // Check our filter mechanism - whether the victim from the main cache should really be evicted
                    // or the key from the front cache shouldn't be moved to the main cache at all 
                    r_victim_key.read(victim_key, 0);
                    r_main_keys.read(main_keys_bit, h);
                    if (victim_key != 0) {
                        bit<COUNTER_SIZE> first_counter;
                        r_counter.read(first_counter, (bit<32>)current_victim[79:64]);
                        bit<COUNTER_SIZE> second_counter;
                        r_counter.read(second_counter, (bit<32>)main_element0[79:64]);
                        if (second_counter < first_counter) {
                            // Our insertion was incorrect
                            main_element0 = current_victim;
                            main_keys_bit[15:0] = current_victim[79:64];
                        }
                    }
                    r_main_keys.write(h, main_keys_bit);

                    main_element = main_element1 ++ main_element0;
                    r_main_cache.write(h, main_element);
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
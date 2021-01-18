
#include <core.p4>
#include <v1model.p4>

#define MAX_ENTRIES 16
#define FRONT_CACHE_SIZE 32
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
    register<bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)>>(MAX_ENTRIES) r_front_cache;

    // Victim element. Common for the two caches.
    register<bit<ELEMENT_SIZE>>(MAX_ENTRIES) r_victim_element;

    // Keys cache
    register<bit<(KEY_SIZE * FRONT_CACHE_SIZE)>>(MAX_ENTRIES) r_front_keys;
    
    // Victim Key. Common for thw two cached
    register<bit<KEY_SIZE>>(MAX_ENTRIES) r_victim_key; 
    
    // Masks to check whether or not the requested key is in the cache
    bit<(KEY_SIZE * FRONT_CACHE_SIZE)> front_keys_mask;
    
    // Bit that represent the keys in the cache
    bit<(KEY_SIZE * FRONT_CACHE_SIZE)> front_keys_bit;
    
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

bit<16> key16 = keys[271:256];
if (index == 16) {
    new_victim_key = key16;
    key16 = key_to_insert;
} 

bit<16> key17 = keys[287:272];
if (index == 17) {
    new_victim_key = key17;
    key17 = key_to_insert;
} 

bit<16> key18 = keys[303:288];
if (index == 18) {
    new_victim_key = key18;
    key18 = key_to_insert;
} 

bit<16> key19 = keys[319:304];
if (index == 19) {
    new_victim_key = key19;
    key19 = key_to_insert;
} 

bit<16> key20 = keys[335:320];
if (index == 20) {
    new_victim_key = key20;
    key20 = key_to_insert;
} 

bit<16> key21 = keys[351:336];
if (index == 21) {
    new_victim_key = key21;
    key21 = key_to_insert;
} 

bit<16> key22 = keys[367:352];
if (index == 22) {
    new_victim_key = key22;
    key22 = key_to_insert;
} 

bit<16> key23 = keys[383:368];
if (index == 23) {
    new_victim_key = key23;
    key23 = key_to_insert;
} 

bit<16> key24 = keys[399:384];
if (index == 24) {
    new_victim_key = key24;
    key24 = key_to_insert;
} 

bit<16> key25 = keys[415:400];
if (index == 25) {
    new_victim_key = key25;
    key25 = key_to_insert;
} 

bit<16> key26 = keys[431:416];
if (index == 26) {
    new_victim_key = key26;
    key26 = key_to_insert;
} 

bit<16> key27 = keys[447:432];
if (index == 27) {
    new_victim_key = key27;
    key27 = key_to_insert;
} 

bit<16> key28 = keys[463:448];
if (index == 28) {
    new_victim_key = key28;
    key28 = key_to_insert;
} 

bit<16> key29 = keys[479:464];
if (index == 29) {
    new_victim_key = key29;
    key29 = key_to_insert;
} 

bit<16> key30 = keys[495:480];
if (index == 30) {
    new_victim_key = key30;
    key30 = key_to_insert;
} 

bit<16> key31 = keys[511:496];
if (index == 31) {
    new_victim_key = key31;
    key31 = key_to_insert;
} 
        keys = key31 ++ key30 ++ key29 ++ key28 ++ key27 ++ key26 ++ key25 ++ key24 ++ key23 ++ key22 ++ key21 ++ key20 ++ key19 ++ key18 ++ key17 ++ key16 ++ key15 ++ key14 ++ key13 ++ key12 ++ key11 ++ key10 ++ key9 ++ key8 ++ key7 ++ key6 ++ key5 ++ key4 ++ key3 ++ key2 ++ key1 ++ key0;
        r_front_keys.write(h, keys);
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

bit<ELEMENT_SIZE> front_element1 = front_element[159:80];
if (index == 1) {
    if (front_element1[79:64] == requested_key) {
        front_element1[31:0] = front_element1[31:0] + 1; // LFU
        front_element1[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element2 = front_element[239:160];
if (index == 2) {
    if (front_element2[79:64] == requested_key) {
        front_element2[31:0] = front_element2[31:0] + 1; // LFU
        front_element2[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element3 = front_element[319:240];
if (index == 3) {
    if (front_element3[79:64] == requested_key) {
        front_element3[31:0] = front_element3[31:0] + 1; // LFU
        front_element3[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element4 = front_element[399:320];
if (index == 4) {
    if (front_element4[79:64] == requested_key) {
        front_element4[31:0] = front_element4[31:0] + 1; // LFU
        front_element4[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element5 = front_element[479:400];
if (index == 5) {
    if (front_element5[79:64] == requested_key) {
        front_element5[31:0] = front_element5[31:0] + 1; // LFU
        front_element5[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element6 = front_element[559:480];
if (index == 6) {
    if (front_element6[79:64] == requested_key) {
        front_element6[31:0] = front_element6[31:0] + 1; // LFU
        front_element6[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element7 = front_element[639:560];
if (index == 7) {
    if (front_element7[79:64] == requested_key) {
        front_element7[31:0] = front_element7[31:0] + 1; // LFU
        front_element7[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element8 = front_element[719:640];
if (index == 8) {
    if (front_element8[79:64] == requested_key) {
        front_element8[31:0] = front_element8[31:0] + 1; // LFU
        front_element8[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element9 = front_element[799:720];
if (index == 9) {
    if (front_element9[79:64] == requested_key) {
        front_element9[31:0] = front_element9[31:0] + 1; // LFU
        front_element9[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element10 = front_element[879:800];
if (index == 10) {
    if (front_element10[79:64] == requested_key) {
        front_element10[31:0] = front_element10[31:0] + 1; // LFU
        front_element10[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element11 = front_element[959:880];
if (index == 11) {
    if (front_element11[79:64] == requested_key) {
        front_element11[31:0] = front_element11[31:0] + 1; // LFU
        front_element11[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element12 = front_element[1039:960];
if (index == 12) {
    if (front_element12[79:64] == requested_key) {
        front_element12[31:0] = front_element12[31:0] + 1; // LFU
        front_element12[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element13 = front_element[1119:1040];
if (index == 13) {
    if (front_element13[79:64] == requested_key) {
        front_element13[31:0] = front_element13[31:0] + 1; // LFU
        front_element13[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element14 = front_element[1199:1120];
if (index == 14) {
    if (front_element14[79:64] == requested_key) {
        front_element14[31:0] = front_element14[31:0] + 1; // LFU
        front_element14[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element15 = front_element[1279:1200];
if (index == 15) {
    if (front_element15[79:64] == requested_key) {
        front_element15[31:0] = front_element15[31:0] + 1; // LFU
        front_element15[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element16 = front_element[1359:1280];
if (index == 16) {
    if (front_element16[79:64] == requested_key) {
        front_element16[31:0] = front_element16[31:0] + 1; // LFU
        front_element16[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element17 = front_element[1439:1360];
if (index == 17) {
    if (front_element17[79:64] == requested_key) {
        front_element17[31:0] = front_element17[31:0] + 1; // LFU
        front_element17[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element18 = front_element[1519:1440];
if (index == 18) {
    if (front_element18[79:64] == requested_key) {
        front_element18[31:0] = front_element18[31:0] + 1; // LFU
        front_element18[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element19 = front_element[1599:1520];
if (index == 19) {
    if (front_element19[79:64] == requested_key) {
        front_element19[31:0] = front_element19[31:0] + 1; // LFU
        front_element19[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element20 = front_element[1679:1600];
if (index == 20) {
    if (front_element20[79:64] == requested_key) {
        front_element20[31:0] = front_element20[31:0] + 1; // LFU
        front_element20[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element21 = front_element[1759:1680];
if (index == 21) {
    if (front_element21[79:64] == requested_key) {
        front_element21[31:0] = front_element21[31:0] + 1; // LFU
        front_element21[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element22 = front_element[1839:1760];
if (index == 22) {
    if (front_element22[79:64] == requested_key) {
        front_element22[31:0] = front_element22[31:0] + 1; // LFU
        front_element22[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element23 = front_element[1919:1840];
if (index == 23) {
    if (front_element23[79:64] == requested_key) {
        front_element23[31:0] = front_element23[31:0] + 1; // LFU
        front_element23[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element24 = front_element[1999:1920];
if (index == 24) {
    if (front_element24[79:64] == requested_key) {
        front_element24[31:0] = front_element24[31:0] + 1; // LFU
        front_element24[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element25 = front_element[2079:2000];
if (index == 25) {
    if (front_element25[79:64] == requested_key) {
        front_element25[31:0] = front_element25[31:0] + 1; // LFU
        front_element25[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element26 = front_element[2159:2080];
if (index == 26) {
    if (front_element26[79:64] == requested_key) {
        front_element26[31:0] = front_element26[31:0] + 1; // LFU
        front_element26[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element27 = front_element[2239:2160];
if (index == 27) {
    if (front_element27[79:64] == requested_key) {
        front_element27[31:0] = front_element27[31:0] + 1; // LFU
        front_element27[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element28 = front_element[2319:2240];
if (index == 28) {
    if (front_element28[79:64] == requested_key) {
        front_element28[31:0] = front_element28[31:0] + 1; // LFU
        front_element28[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element29 = front_element[2399:2320];
if (index == 29) {
    if (front_element29[79:64] == requested_key) {
        front_element29[31:0] = front_element29[31:0] + 1; // LFU
        front_element29[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element30 = front_element[2479:2400];
if (index == 30) {
    if (front_element30[79:64] == requested_key) {
        front_element30[31:0] = front_element30[31:0] + 1; // LFU
        front_element30[63:32] = timestamp; //LRU
    }
}

bit<ELEMENT_SIZE> front_element31 = front_element[2559:2480];
if (index == 31) {
    if (front_element31[79:64] == requested_key) {
        front_element31[31:0] = front_element31[31:0] + 1; // LFU
        front_element31[63:32] = timestamp; //LRU
    }
}

        front_element = front_element31 ++ front_element30 ++ front_element29 ++ front_element28 ++ front_element27 ++ front_element26 ++ front_element25 ++ front_element24 ++ front_element23 ++ front_element22 ++ front_element21 ++ front_element20 ++ front_element19 ++ front_element18 ++ front_element17 ++ front_element16 ++ front_element15 ++ front_element14 ++ front_element13 ++ front_element12 ++ front_element11 ++ front_element10 ++ front_element9 ++ front_element8 ++ front_element7 ++ front_element6 ++ front_element5 ++ front_element4 ++ front_element3 ++ front_element2 ++ front_element1 ++ front_element0;
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

    action insert_to_front_cache_first_element(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element, in bit<32> timestamp) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;

        insert_to_cache_inner(index, requested_key, 1, timestamp, element);

        // Insert the key to the keys_register
        bit<KEY_SIZE> next_victim;
        insert_key_to_front_keys_register(h, index, hdr.p4kway.k, next_victim);
        r_victim_key.write(0, next_victim);
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

    action mark_front_hit() {
	    hdr.p4kway.front = 1;
    }

    action mark_front_miss() {
	    hdr.p4kway.front = 0;
    }

    action skip() { 
        // Do nothing
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
	        512w0x0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0xFFFF0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x0000FFFF000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x00000000FFFF00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x000000000000FFFF0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x0000000000000000FFFF000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x00000000000000000000FFFF00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x000000000000000000000000FFFF0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x0000000000000000000000000000FFFF000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x00000000000000000000000000000000FFFF00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x000000000000000000000000000000000000FFFF0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x0000000000000000000000000000000000000000FFFF000000000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x00000000000000000000000000000000000000000000FFFF00000000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x000000000000000000000000000000000000000000000000FFFF0000000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x0000000000000000000000000000000000000000000000000000FFFF000000000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x00000000000000000000000000000000000000000000000000000000FFFF00000000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x000000000000000000000000000000000000000000000000000000000000FFFF0000000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x0000000000000000000000000000000000000000000000000000000000000000FFFF000000000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x00000000000000000000000000000000000000000000000000000000000000000000FFFF00000000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x000000000000000000000000000000000000000000000000000000000000000000000000FFFF0000000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x0000000000000000000000000000000000000000000000000000000000000000000000000000FFFF000000000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x00000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF00000000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF0000000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF000000000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF00000000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF0000000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFFFFFF &&& 512w0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF000000000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFFFFFF &&& 512w0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF00000000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFFFFFF &&& 512w0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF0000000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFFFFFF &&& 512w0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF000000000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFFFFFF &&& 512w0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF00000000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000FFFF &&& 512w0x000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF0000: mark_front_hit();
512w0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0000 &&& 512w0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000FFFF: mark_front_hit();
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
            front_keys_mask = (hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k ++ hdr.p4kway.k) ^ front_keys_bit;

            check_front_cache.apply();
            noop_front.apply();
            noop_key.apply();

            
            if (hdr.p4kway.front == 1) {
                // Retrieve from front cache
                get_element_from_front_cache(h ,0, current_timestamp);
get_element_from_front_cache(h ,1, current_timestamp);
get_element_from_front_cache(h ,2, current_timestamp);
get_element_from_front_cache(h ,3, current_timestamp);
get_element_from_front_cache(h ,4, current_timestamp);
get_element_from_front_cache(h ,5, current_timestamp);
get_element_from_front_cache(h ,6, current_timestamp);
get_element_from_front_cache(h ,7, current_timestamp);
get_element_from_front_cache(h ,8, current_timestamp);
get_element_from_front_cache(h ,9, current_timestamp);
get_element_from_front_cache(h ,10, current_timestamp);
get_element_from_front_cache(h ,11, current_timestamp);
get_element_from_front_cache(h ,12, current_timestamp);
get_element_from_front_cache(h ,13, current_timestamp);
get_element_from_front_cache(h ,14, current_timestamp);
get_element_from_front_cache(h ,15, current_timestamp);
get_element_from_front_cache(h ,16, current_timestamp);
get_element_from_front_cache(h ,17, current_timestamp);
get_element_from_front_cache(h ,18, current_timestamp);
get_element_from_front_cache(h ,19, current_timestamp);
get_element_from_front_cache(h ,20, current_timestamp);
get_element_from_front_cache(h ,21, current_timestamp);
get_element_from_front_cache(h ,22, current_timestamp);
get_element_from_front_cache(h ,23, current_timestamp);
get_element_from_front_cache(h ,24, current_timestamp);
get_element_from_front_cache(h ,25, current_timestamp);
get_element_from_front_cache(h ,26, current_timestamp);
get_element_from_front_cache(h ,27, current_timestamp);
get_element_from_front_cache(h ,28, current_timestamp);
get_element_from_front_cache(h ,29, current_timestamp);
get_element_from_front_cache(h ,30, current_timestamp);
get_element_from_front_cache(h ,31, current_timestamp);

            } else {
                bit<ELEMENT_SIZE> current_victim = 0;
                bit<KEY_SIZE> victim_key = 0;
                bool insert = true;

                // Insert to front cache
                bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> front_element;
                r_front_cache.read(front_element, h);

                bit<ELEMENT_SIZE> front_element0 = front_element[79:0];
                insert_to_front_cache_first_element(h, 0, front_element0, current_timestamp);

                
bit<ELEMENT_SIZE> front_element1 = front_element[159:80];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element1[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element1[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 1, front_element1, current_timestamp);
    } else {
        //if (front_element1[31:0] > 0) {
        //    front_element1[31:0] = front_element1[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element2 = front_element[239:160];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element2[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element2[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 2, front_element2, current_timestamp);
    } else {
        //if (front_element2[31:0] > 0) {
        //    front_element2[31:0] = front_element2[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element3 = front_element[319:240];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element3[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element3[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 3, front_element3, current_timestamp);
    } else {
        //if (front_element3[31:0] > 0) {
        //    front_element3[31:0] = front_element3[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element4 = front_element[399:320];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element4[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element4[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 4, front_element4, current_timestamp);
    } else {
        //if (front_element4[31:0] > 0) {
        //    front_element4[31:0] = front_element4[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element5 = front_element[479:400];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element5[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element5[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 5, front_element5, current_timestamp);
    } else {
        //if (front_element5[31:0] > 0) {
        //    front_element5[31:0] = front_element5[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element6 = front_element[559:480];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element6[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element6[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 6, front_element6, current_timestamp);
    } else {
        //if (front_element6[31:0] > 0) {
        //    front_element6[31:0] = front_element6[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element7 = front_element[639:560];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element7[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element7[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 7, front_element7, current_timestamp);
    } else {
        //if (front_element7[31:0] > 0) {
        //    front_element7[31:0] = front_element7[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element8 = front_element[719:640];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element8[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element8[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 8, front_element8, current_timestamp);
    } else {
        //if (front_element8[31:0] > 0) {
        //    front_element8[31:0] = front_element8[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element9 = front_element[799:720];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element9[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element9[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 9, front_element9, current_timestamp);
    } else {
        //if (front_element9[31:0] > 0) {
        //    front_element9[31:0] = front_element9[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element10 = front_element[879:800];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element10[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element10[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 10, front_element10, current_timestamp);
    } else {
        //if (front_element10[31:0] > 0) {
        //    front_element10[31:0] = front_element10[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element11 = front_element[959:880];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element11[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element11[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 11, front_element11, current_timestamp);
    } else {
        //if (front_element11[31:0] > 0) {
        //    front_element11[31:0] = front_element11[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element12 = front_element[1039:960];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element12[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element12[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 12, front_element12, current_timestamp);
    } else {
        //if (front_element12[31:0] > 0) {
        //    front_element12[31:0] = front_element12[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element13 = front_element[1119:1040];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element13[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element13[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 13, front_element13, current_timestamp);
    } else {
        //if (front_element13[31:0] > 0) {
        //    front_element13[31:0] = front_element13[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element14 = front_element[1199:1120];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element14[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element14[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 14, front_element14, current_timestamp);
    } else {
        //if (front_element14[31:0] > 0) {
        //    front_element14[31:0] = front_element14[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element15 = front_element[1279:1200];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element15[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element15[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 15, front_element15, current_timestamp);
    } else {
        //if (front_element15[31:0] > 0) {
        //    front_element15[31:0] = front_element15[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element16 = front_element[1359:1280];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element16[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element16[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 16, front_element16, current_timestamp);
    } else {
        //if (front_element16[31:0] > 0) {
        //    front_element16[31:0] = front_element16[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element17 = front_element[1439:1360];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element17[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element17[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 17, front_element17, current_timestamp);
    } else {
        //if (front_element17[31:0] > 0) {
        //    front_element17[31:0] = front_element17[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element18 = front_element[1519:1440];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element18[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element18[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 18, front_element18, current_timestamp);
    } else {
        //if (front_element18[31:0] > 0) {
        //    front_element18[31:0] = front_element18[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element19 = front_element[1599:1520];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element19[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element19[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 19, front_element19, current_timestamp);
    } else {
        //if (front_element19[31:0] > 0) {
        //    front_element19[31:0] = front_element19[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element20 = front_element[1679:1600];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element20[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element20[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 20, front_element20, current_timestamp);
    } else {
        //if (front_element20[31:0] > 0) {
        //    front_element20[31:0] = front_element20[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element21 = front_element[1759:1680];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element21[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element21[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 21, front_element21, current_timestamp);
    } else {
        //if (front_element21[31:0] > 0) {
        //    front_element21[31:0] = front_element21[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element22 = front_element[1839:1760];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element22[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element22[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 22, front_element22, current_timestamp);
    } else {
        //if (front_element22[31:0] > 0) {
        //    front_element22[31:0] = front_element22[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element23 = front_element[1919:1840];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element23[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element23[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 23, front_element23, current_timestamp);
    } else {
        //if (front_element23[31:0] > 0) {
        //    front_element23[31:0] = front_element23[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element24 = front_element[1999:1920];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element24[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element24[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 24, front_element24, current_timestamp);
    } else {
        //if (front_element24[31:0] > 0) {
        //    front_element24[31:0] = front_element24[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element25 = front_element[2079:2000];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element25[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element25[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 25, front_element25, current_timestamp);
    } else {
        //if (front_element25[31:0] > 0) {
        //    front_element25[31:0] = front_element25[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element26 = front_element[2159:2080];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element26[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element26[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 26, front_element26, current_timestamp);
    } else {
        //if (front_element26[31:0] > 0) {
        //    front_element26[31:0] = front_element26[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element27 = front_element[2239:2160];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element27[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element27[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 27, front_element27, current_timestamp);
    } else {
        //if (front_element27[31:0] > 0) {
        //    front_element27[31:0] = front_element27[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element28 = front_element[2319:2240];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element28[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element28[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 28, front_element28, current_timestamp);
    } else {
        //if (front_element28[31:0] > 0) {
        //    front_element28[31:0] = front_element28[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element29 = front_element[2399:2320];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element29[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element29[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 29, front_element29, current_timestamp);
    } else {
        //if (front_element29[31:0] > 0) {
        //    front_element29[31:0] = front_element29[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element30 = front_element[2479:2400];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element30[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element30[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 30, front_element30, current_timestamp);
    } else {
        //if (front_element30[31:0] > 0) {
        //    front_element30[31:0] = front_element30[31:0] - 1;
        //}
    }
}

bit<ELEMENT_SIZE> front_element31 = front_element[2559:2480];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.front_type == P4GET_VAL_LFU && front_element31[31:0] > current_victim[31:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.front_type == P4GET_VAL_LRU && front_element31[63:32] > current_victim[63:32]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_front_cache(h, 31, front_element31, current_timestamp);
    } else {
        //if (front_element31[31:0] > 0) {
        //    front_element31[31:0] = front_element31[31:0] - 1;
        //}
    }
}

                front_element = front_element31 ++ front_element30 ++ front_element29 ++ front_element28 ++ front_element27 ++ front_element26 ++ front_element25 ++ front_element24 ++ front_element23 ++ front_element22 ++ front_element21 ++ front_element20 ++ front_element19 ++ front_element18 ++ front_element17 ++ front_element16 ++ front_element15 ++ front_element14 ++ front_element13 ++ front_element12 ++ front_element11 ++ front_element10 ++ front_element9 ++ front_element8 ++ front_element7 ++ front_element6 ++ front_element5 ++ front_element4 ++ front_element3 ++ front_element2 ++ front_element1 ++ front_element0;
                r_front_cache.write(h, front_element);

                r_victim_key.read(victim_key, 0);
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
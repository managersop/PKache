from jinja2 import Template

P4_TEMPLATE = Template('''
#include <core.p4>
#include <v1model.p4>

#define MAX_ENTRIES {{max_entries_size}}
#define FRONT_CACHE_SIZE {{front_cache_size}}
#define ELEMENT_SIZE {{counter_size + counter_size + key_size}}
#define KEY_SIZE {{key_size}}
#define COUNTER_SIZE {{counter_size}}

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
   bit<{{key_size}}> k;
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

    register<bit<(COUNTER_SIZE)>>({{2 ** key_size - 1}}) r_counter;
    register<bit<{{counter_size}}>>(1) r_timestamp;

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
        {{insert_key_to_front}}
        keys = {{build_front_keys_element}};
        r_front_keys.write(h, keys);
    }

    action get_element_from_front_cache(in bit<32> h, in bit<32> index, in bit<32> timestamp) {
        bit<KEY_SIZE> requested_key = hdr.p4kway.k;
        bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> front_element;

        r_front_cache.read(front_element, h);
        {{get_element_from_front_cache}}

        front_element = {{build_front_element}};
        r_front_cache.write(h, front_element);
    }

    action insert_to_cache_inner(in bit<32> index, in bit<KEY_SIZE> k, in bit<32> c, in bit<32> timestamp, inout bit<ELEMENT_SIZE> element) {
        bit<ELEMENT_SIZE> victim_element = 0;
        victim_element[{{2*counter_size + key_size - 1}}:{{2*counter_size}}] = element[{{2*counter_size + key_size - 1}}:{{2*counter_size}}]; //k
        victim_element[{{counter_size - 1}}:0] = element[{{counter_size - 1}}:0];   //LFU
        victim_element[{{2*counter_size - 1}}:{{counter_size}}] = element[{{2*counter_size - 1}}:{{counter_size}}];   //LRU
        //if (victim_element[{{counter_size - 1}}:0] > 0) {
        //    victim_element[{{counter_size - 1}}:0] = victim_element[{{counter_size - 1}}:0] - 1;
        //}
        r_victim_element.write(0, victim_element);

         // Update cache[0] to be the new element 
        element[{{2*counter_size + key_size - 1}}:{{2*counter_size}}] = k;
        element[{{2*counter_size - 1}}:{{counter_size}}] = timestamp; // LRU
        element[{{counter_size - 1}}:0] = c; //LFU
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

        insert_to_cache_inner(index, current_victim[{{2*counter_size + key_size - 1}}:{{2*counter_size}}], current_victim[{{counter_size - 1}}:0], timestamp, element);

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
	        {{tcam_front_cache}}
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
            {{deamortization}}
            current_timestamp = current_timestamp + 1;
            r_timestamp.write(0, current_timestamp);
            
            r_counter.read(counter_value, (bit<32>)hdr.p4kway.k);
            counter_value = counter_value + 1;
            r_counter.write((bit<32>)hdr.p4kway.k, counter_value);
            

            bit<32> h = (bit<32>)hdr.p4kway.k % MAX_ENTRIES;
            r_front_keys.read(front_keys_bit, h);
            front_keys_mask = ({{front_keys_mask}}) ^ front_keys_bit;

            check_front_cache.apply();
            noop_front.apply();
            noop_key.apply();

            
            if (hdr.p4kway.front == 1) {
                // Retrieve from front cache
                {{retrieve_from_front_cache}}

            } else {
                bit<ELEMENT_SIZE> current_victim = 0;
                bit<KEY_SIZE> victim_key = 0;
                bool insert = true;

                // Insert to front cache
                bit<(ELEMENT_SIZE * FRONT_CACHE_SIZE)> front_element;
                r_front_cache.read(front_element, h);

                bit<ELEMENT_SIZE> front_element0 = front_element[{{2*counter_size + key_size - 1}}:0];
                insert_to_front_cache_first_element(h, 0, front_element0, current_timestamp);

                {{front_actions}}

                front_element = {{build_front_element}};
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
''')


MAIN_ACTION_TEMPLATE = Template('''
bit<ELEMENT_SIZE> {{type}}_element{{i}} = {{type}}_element[{{(2*counter_size+key_size)*(i+1)-1}}:{{(2*counter_size+key_size)*i}}];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);
insert = true;
if (victim_key != 0) {
    if (hdr.p4kway.{{type}}_type == P4GET_VAL_LFU && {{type}}_element{{i}}[{{counter_size-1}}:0] > current_victim[{{counter_size-1}}:0]) {
        // Do nothing
        insert = false;
    } 
    if (hdr.p4kway.{{type}}_type == P4GET_VAL_LRU && {{type}}_element{{i}}[{{2*counter_size-1}}:{{counter_size}}] > current_victim[{{2*counter_size-1}}:{{counter_size}}]) {
        // Do nothing
        insert = false;
    } 
    if (insert) {
        insert_to_{{type}}_cache(h, {{i}}, {{type}}_element{{i}}, current_timestamp);
    } else {
        //if ({{type}}_element{{i}}[{{counter_size-1}}:0] > 0) {
        //    {{type}}_element{{i}}[{{counter_size-1}}:0] = {{type}}_element{{i}}[{{counter_size-1}}:0] - 1;
        //}
    }
}
''')

RETREIVE_FROM_CACHE_TEMPLATE = Template('''get_element_from_{{type}}_cache(h ,{{i}}, current_timestamp);''')
BUILD_ELEMENT_TEMPLATE = Template('''{{type}}_element{{i}}''')
GET_ELEMENT_FROM_CACHE_TEMPLATE = Template('''
bit<ELEMENT_SIZE> {{type}}_element{{i}} = {{type}}_element[{{(2*counter_size+key_size)*(i+1)-1}}:{{(2*counter_size+key_size)*i}}];
if (index == {{i}}) {
    if ({{type}}_element{{i}}[{{2*counter_size+key_size-1}}:{{2*counter_size}}] == requested_key) {
        {{type}}_element{{i}}[{{counter_size-1}}:0] = {{type}}_element{{i}}[{{counter_size-1}}:0] + 1; // LFU
        {{type}}_element{{i}}[{{2*counter_size-1}}:{{counter_size}}] = timestamp; //LRU
    }
}
''')


DEAMORTIZATION_PROCESS_TEMPLATE = Template('''
if (current_timestamp == {{8 * (i+1)}}) {
    {{deamortization_inner}}
}
''')

DEAMORTIZATION_INNER_TEMPLATE = Template('''
r_counter.read(counter_value, {{i}});
counter_value = counter_value << 1;
r_counter.write({{i}}, counter_value);
''')

def get_first_mask(size, index, key_size):
    l = key_size // 4
    mask = ['F' * l] * size
    mask[index] = '0' * l
    return ''.join(mask)

def get_second_mask(size, index, key_size):
    l = key_size // 4
    mask = ['0' * l] * size
    mask[index] = 'F' * l
    return ''.join(mask)

TCAM_TEMPLATE = Template('''{{key_size * cache_size}}w0x{{get_first_mask(cache_size, i, key_size)}} &&& {{key_size * cache_size}}w0x{{get_second_mask(cache_size, i, key_size)}}: mark_{{type}}_hit();''')

INSERT_KEY_TO_KEY_REGISTER = Template('''
bit<{{key_size}}> key{{i}} = keys[{{key_size*(i+1)-1}}:{{key_size*i}}];
if (index == {{i}}) {
    new_victim_key = key{{i}};
    key{{i}} = key_to_insert;
} 
''')

BUILD_KEY_TEMPLATE = Template('''key{{i}}''')


if __name__ == "__main__":
    max_entries_size = 1
    main_cache_size = 2
    front_cache_size = 1
    key_size = 16
    counter_size = 32
    
    main_actions = '\n'.join(list(map(lambda x: MAIN_ACTION_TEMPLATE.render(i=x, type="main", key_size=key_size, counter_size=counter_size), range(1,main_cache_size))))
    front_actions = '\n'.join(list(map(lambda x: MAIN_ACTION_TEMPLATE.render(i=x, type="front", key_size=key_size, counter_size=counter_size), range(1, front_cache_size))))
    
    retrive_from_main_cache = '\n'.join(list(map(lambda x: RETREIVE_FROM_CACHE_TEMPLATE.render(i=x, type="main", key_size=key_size, counter_size=counter_size), range(main_cache_size))))
    retrive_from_front_cache = '\n'.join(list(map(lambda x: RETREIVE_FROM_CACHE_TEMPLATE.render(i=x, type="front", key_size=key_size, counter_size=counter_size), range(front_cache_size))))
    
    build_main_element = ' ++ '.join(list(map(lambda x: BUILD_ELEMENT_TEMPLATE.render(i=x,  type="main", key_size=key_size, counter_size=counter_size), reversed(range(main_cache_size)))))
    build_front_element = ' ++ '.join(list(map(lambda x: BUILD_ELEMENT_TEMPLATE.render(i=x, type="front", key_size=key_size, counter_size=counter_size), reversed(range(front_cache_size)))))
    
    main_keys_mask = ' ++ '.join(['hdr.p4kway.k'] * main_cache_size)
    front_keys_mask = ' ++ '.join(['hdr.p4kway.k'] * front_cache_size)

    TCAM_TEMPLATE.globals['get_first_mask'] = get_first_mask
    TCAM_TEMPLATE.globals['get_second_mask'] = get_second_mask
    tcam_main_cache = '\n'.join(list(map(lambda x: TCAM_TEMPLATE.render(i=x, cache_size=main_cache_size, type="main", key_size=key_size, counter_size=counter_size), range(main_cache_size))))
    tcam_front_cache = '\n'.join(list(map(lambda x: TCAM_TEMPLATE.render(i=x, cache_size=front_cache_size, type="front", key_size=key_size, counter_size=counter_size), range(front_cache_size))))
    
    get_element_from_main_cache = '\n'.join(list(map(lambda x: GET_ELEMENT_FROM_CACHE_TEMPLATE.render(i=x, type="main", key_size=key_size, counter_size=counter_size), range(main_cache_size))))
    get_element_from_front_cache = '\n'.join(list(map(lambda x: GET_ELEMENT_FROM_CACHE_TEMPLATE.render(i=x, type="front", key_size=key_size, counter_size=counter_size), range(front_cache_size))))
    
    insert_key_to_main = '\n'.join(list(map(lambda x: INSERT_KEY_TO_KEY_REGISTER.render(i=x, key_size=key_size, counter_size=counter_size), range(main_cache_size))))
    insert_key_to_front = '\n'.join(list(map(lambda x: INSERT_KEY_TO_KEY_REGISTER.render(i=x, key_size=key_size, counter_size=counter_size), range(front_cache_size))))

    build_main_key = ' ++ '.join(list(map(lambda x: BUILD_KEY_TEMPLATE.render(i=x), reversed(range(main_cache_size)))))
    build_front_key = ' ++ '.join(list(map(lambda x: BUILD_KEY_TEMPLATE.render(i=x), reversed(range(front_cache_size)))))


    # deamortization = ''
    # max_rounds_until_deamortization = max_entries_size * main_cache_size
    # size_of_each_deamortization = int((2 ** (key_size) / max_rounds_until_deamortization))
    # print (size_of_each_deamortization)

    # for i in range(max_rounds_until_deamortization):
    #     deamortzation_inner = '\n'.join(list(map(lambda x: DEAMORTIZATION_INNER_TEMPLATE.render(i=x), range(i * size_of_each_deamortization, (i+1) * size_of_each_deamortization))))
    #     #print(deamortzation_inner)
    #     deamortization += DEAMORTIZATION_PROCESS_TEMPLATE.render(i=i, deamortization_inner=deamortzation_inner) + '\n'


    

    p4_generated_file = (P4_TEMPLATE.render
                        (
                            max_entries_size=max_entries_size,
                            key_size=key_size,          
                            main_cache_size=main_cache_size,
                            max_turns=8*main_cache_size*max_entries_size,
                            counter_size=counter_size,
                            front_cache_size=front_cache_size,
                            insert_key_to_main=insert_key_to_main,
                            insert_key_to_front=insert_key_to_front,
                            build_main_keys_element = build_main_key,
                            build_front_keys_element = build_front_key,
                            retrieve_from_main_cache=retrive_from_main_cache,
                            retrieve_from_front_cache=retrive_from_front_cache,
                            main_actions=main_actions,
                            front_actions=front_actions,
                            build_main_element=build_main_element,
                            build_front_element=build_front_element,
                            main_keys_mask=main_keys_mask,
                            front_keys_mask=front_keys_mask,
                            tcam_main_cache=tcam_main_cache,
                            tcam_front_cache=tcam_front_cache,
                            get_element_from_main_cache=get_element_from_main_cache,
                            get_element_from_front_cache=get_element_from_front_cache,
                            #deamortization=deamortization
                        )
            )

    # print(p4_generated_file)

    with open('./cahceway.p4', 'w') as f:
        f.write(p4_generated_file)
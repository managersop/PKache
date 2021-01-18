from jinja2 import Template

P4_TEMPLATE = Template('''
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */
#define MAX_ENTRIES {{max_entries_size}}
#define CACHE_SIZE {{cache_size}}
#define ELEMENT_SIZE {{counter_size + access_size + key_size}}
#define KEY_SIZE {{key_size}}
#define COUNTER_SIZE {{counter_size}}
#define LOG_REGISTER_SIZE {{log_size}}
#define ACCESS_SIZE {{access_size}}
#define PERIOD_SIZE {{period_size}}

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
   bit<{{key_size}}> k;
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
        {{get_element_from_cache}}

        element = {{build_element}};
        r_cache.write(h, element);
    }

    action insert_key_to_keys_register(in bit<32> h, in bit<32> index, in bit<KEY_SIZE> key_to_insert, out bit<KEY_SIZE> new_victim_key) {
        new_victim_key = 0;
        bit<(KEY_SIZE * CACHE_SIZE)> keys;
        r_keys.read(keys, h);
        {{insert_key}}
        keys = {{build_keys_element}};
        r_keys.write(h, keys);
    }

    action insert_to_cache_inner(in bit<32> index, in bit<KEY_SIZE> k, in bit<COUNTER_SIZE> scn, in bit<ACCESS_SIZE> access, inout bit<ELEMENT_SIZE> element) {
        bit<ELEMENT_SIZE> victim_element = 0;
        victim_element[{{counter_size + access_size + key_size - 1}}:{{counter_size + access_size}}] = element[{{counter_size + access_size + key_size - 1}}:{{counter_size + access_size}}];
        victim_element[{{counter_size + access_size - 1}}:{{counter_size}}] = element[{{counter_size + access_size - 1}}:{{counter_size}}];
        victim_element[{{counter_size - 1}}:0] = element[{{counter_size - 1}}:0];
        r_victim_element.write(0, victim_element);

        element[{{counter_size + access_size + key_size - 1}}:{{counter_size + access_size}}] = k;
        element[{{counter_size + access_size - 1}}:{{counter_size}}] = access;
        element[{{counter_size - 1}}:0] = scn;
    }

    action insert_to_cache(in bit<32> h, in bit<32> index, inout bit<ELEMENT_SIZE> element, in bit<COUNTER_SIZE> scn) {
        bit<ELEMENT_SIZE> current_victim;
        r_victim_element.read(current_victim, 0);

        insert_to_cache_inner(index, current_victim[{{counter_size + access_size + key_size - 1}}:{{counter_size + access_size}}], scn,current_victim[{{counter_size + access_size - 1}}:{{counter_size}}], element);

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
	        {{tcam_cache}}
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
                keys_mask = ({{keys_mask}}) ^ keys_bit;

                bit<COUNTER_SIZE> scn;
                r_conf.read(scn, 0);
                scn = scn + 1;
                r_conf.write(0, scn);

                check_cache.apply();

                if (hdr.p4kway.cache == 1) {
                    {{retrieve_from_cache}}
                } else {
                    bit<ELEMENT_SIZE> current_victim = 0;
                    bit<KEY_SIZE> victim_key = 0;
                    bit<(ELEMENT_SIZE * CACHE_SIZE)> element;
                    r_cache.read(element, h);

                    bit<ELEMENT_SIZE> element0 = element[{{counter_size + access_size + key_size - 1}}:0];
                    insert_to_cache_first_element(h, 0, element0, scn);
                    bit<PERIOD_SIZE> pr_1;
                    bit<PERIOD_SIZE> pr_2;
                    {{actions}}

                    element = {{build_element}};
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
''')


MAIN_ACTION_TEMPLATE = Template('''
bit<ELEMENT_SIZE> element{{i}} = element[{{(counter_size + access_size + key_size)*(i+1)-1}}:{{(counter_size + access_size + key_size)*i}}];
r_victim_element.read(current_victim, 0);
r_victim_key.read(victim_key, 0);

// Conditional execution in actions is not supported on this target
get_hyperbolic_cache_pr(element{{i}}[{{counter_size + access_size - 1}}:{{counter_size}}], (scn - element{{i}}[{{counter_size - 1}}:0]), pr_1);
get_hyperbolic_cache_pr(current_victim[{{counter_size + access_size - 1}}:{{counter_size}}], (scn - current_victim[{{counter_size - 1}}:0]), pr_2);

if (pr_2 >= pr_1) {
    insert_to_cache(h, {{i}}, element{{i}}, scn);
}
''')

RETREIVE_FROM_CACHE_TEMPLATE = Template('''get_element_from_cache(h ,{{i}});''')
BUILD_ELEMENT_TEMPLATE = Template('''element{{i}}''')
GET_ELEMENT_FROM_CACHE_TEMPLATE = Template('''
bit<ELEMENT_SIZE> element{{i}} = element[{{(counter_size + access_size + key_size)*(i+1)-1}}:{{(counter_size + access_size + key_size)*i}}];
if (index == {{i}}) {
    if (element{{i}}[{{counter_size + access_size + key_size - 1}}:{{counter_size + access_size}}] == requested_key) {
        element{{i}}[{{counter_size + access_size - 1}}:{{counter_size}}] = element{{i}}[{{counter_size + access_size - 1}}:{{counter_size}}] + 1;
    }
}
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

TCAM_TEMPLATE = Template('''{{key_size * cache_size}}w0x{{get_first_mask(cache_size, i, key_size)}} &&& {{key_size * cache_size}}w0x{{get_second_mask(cache_size, i, key_size)}}: mark_hit();''')

INSERT_KEY_TO_KEY_REGISTER = Template('''
bit<{{key_size}}> key{{i}} = keys[{{key_size*(i+1)-1}}:{{key_size*i}}];
if (index == {{i}}) {
    new_victim_key = key{{i}};
    key{{i}} = key_to_insert;
} 
''')

BUILD_KEY_TEMPLATE = Template('''key{{i}}''')


if __name__ == "__main__":
    max_entries_size = 16
    cache_size = 16
    key_size = 16
    counter_size = 16
    period_size = 16
    access_size = 16
    log_size = 65536
    
    actions = '\n'.join(list(map(lambda x: MAIN_ACTION_TEMPLATE.render(i=x, key_size=key_size, counter_size=counter_size, access_size=access_size), range(1, cache_size))))
    
    retrive_from_cache = '\n'.join(list(map(lambda x: RETREIVE_FROM_CACHE_TEMPLATE.render(i=x, key_size=key_size, counter_size=counter_size), range(cache_size))))
    
    build_element = ' ++ '.join(list(map(lambda x: BUILD_ELEMENT_TEMPLATE.render(i=x, key_size=key_size, counter_size=counter_size), reversed(range(cache_size)))))
    
    keys_mask = ' ++ '.join(['hdr.p4kway.k'] * cache_size)

    TCAM_TEMPLATE.globals['get_first_mask'] = get_first_mask
    TCAM_TEMPLATE.globals['get_second_mask'] = get_second_mask
    tcam_cache = '\n'.join(list(map(lambda x: TCAM_TEMPLATE.render(i=x, cache_size=cache_size, key_size=key_size, counter_size=counter_size), range(cache_size))))
    
    get_element_from_cache = '\n'.join(list(map(lambda x: GET_ELEMENT_FROM_CACHE_TEMPLATE.render(i=x, key_size=key_size, counter_size=counter_size, access_size=access_size), range(cache_size))))
    
    insert_key = '\n'.join(list(map(lambda x: INSERT_KEY_TO_KEY_REGISTER.render(i=x, key_size=key_size, counter_size=counter_size), range(cache_size))))

    build_key = ' ++ '.join(list(map(lambda x: BUILD_KEY_TEMPLATE.render(i=x), reversed(range(cache_size)))))

    p4_generated_file = (P4_TEMPLATE.render
                        (
                            max_entries_size=max_entries_size,
                            key_size=key_size,          
                            counter_size=counter_size,
                            cache_size=cache_size,
                            period_size=period_size,
                            access_size=access_size,
                            log_size=log_size,
                            insert_key=insert_key,
                            build_keys_element = build_key,
                            retrieve_from_cache=retrive_from_cache,
                            actions=actions,
                            build_element=build_element,
                            keys_mask=keys_mask,
                            tcam_cache=tcam_cache,
                            get_element_from_cache=get_element_from_cache,
                        )
            )

    # print(p4_generated_file)

    with open('./cahceway.p4', 'w') as f:
        f.write(p4_generated_file)
#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct
import re
import math

from scapy.all import sendp, send, srp1
from scapy.all import Packet, hexdump
from scapy.all import Ether, StrFixedLenField, XByteField, XShortField, BitField
from scapy.all import bind_layers
import readline

class P4kway(Packet):
    name = "p4kway"
    fields_desc = [ StrFixedLenField("P", "P", length=1),
                    StrFixedLenField("Four", "4", length=1),
                    XByteField("version", 0x01),
                    StrFixedLenField("type", "F", length=1),
                    BitField("k", 0, 16),
                    BitField("v", 0, 16),
                    BitField("cache", 0, 8),
                    ]


bind_layers(Ether, P4kway, type=0x1234)


def main():
    s = ''
    iface = 'eth0'
    print("Updating log table")
    for i in range(1, 1000):
        pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / P4kway(type='U', k=i, v=int(round(math.log(i, 2) * 100)))
        pkt = pkt / ' '

        resp = srp1(pkt, iface=iface, timeout=1, verbose=False)
        print(i)
    print("Finish updating log table")

    iface = 'eth0'
    t1 = LFU
    t2 = LRU
    # with open('OLTP.lis', 'r') as f:
    #     data = list(filter(lambda x: x < 65530, map (lambda x: int(x.split(' ')[0]), f.readlines())))
    # with open('WebSearch1.spc', 'r') as f:
    #     data = list(map (lambda x: int(x.split(',')[1]), f.readlines()))
    with open('OLTP.lis', 'r') as f:
        data = list(filter(lambda x: x < 1000, map (lambda x: int(x.split(' ')[0]), f.readlines())))
    # with open('query.txt', 'r') as f:
    #     data = list(map (lambda x: int(x), f.readlines()))
    print len(data)
    hit_front = 0
    hit_main = 0
    hit_miss = 0
    i = 0

    for x in data[:10000]:
        pkt = Ether(dst='00:04:00:00:00:00', type=0x1234) / P4kway(type='P', k=int(x))
        pkt = pkt/' '

        i += 1
        resp = srp1(pkt, iface=iface, timeout=3, verbose=False)
        # print int(x)
        
        if resp:
            p4kway=resp[P4kway]
            # print('key={}, {}, from_cache={}, from_front={}'.format(p4kway.k, int(x)%16, p4kway.cache, p4kway.front))
            if p4kway:
                if p4kway.cache == 1:
                    hit_main += 1
                    #print int(x), int(x)%16, (0, 1, 0)
                else:
                    hit_miss += 1
                    #print int(x), int(x)%16, (0, 0, 1)

                if (i > 0  and i % 100 == 0):
                    print i
                    print 'Hit front ', hit_front
                    print 'Hit main ', hit_main
                    print 'Hit miss ', hit_miss 
                    print(float(hit_front + hit_main) / float((hit_front+hit_main+hit_miss)))



                # print('key={}, value={}, from_cache={}, from_front={}'.format(p4kway.k, p4kway.v, p4kway.cache, p4kway.front))
            else:
                pass
                print "cannot find P4aggregate header in the packet"
        else:
            print 'ERROR'
    print 'Hit front ', hit_front
    print 'Hit main ', hit_main
    print 'Hit miss ', hit_miss 
    print(float(hit_front + hit_main) / float((hit_front+hit_main+hit_miss)))



if __name__ == '__main__':
    main()

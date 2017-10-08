#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
from datetime import datetime, timezone, timedelta
import socket
import hashlib
from operator import attrgetter

from coinflow.protocol.messages import Message, Version, Verack, Addr
from coinflow.protocol.structs import netaddr

def test_version():
    version = 70001
    services = 0
    timestamp = datetime.now(timezone.utc).replace(microsecond=0)
    addr_recv = netaddr('8.8.8.8', 8333, 0)
    addr_from = netaddr('127.0.0.1', 8333, 0)
    nonce = 0xdeadbeaf
    user_agent = 'coinflow test'
    start_height = 1337
    relay = False
    magic = 0xdeadbeaf
    checksum = b'\xca\x97\x81\x12'

    msg = Version(addr_recv, addr_from, version, services, timestamp, nonce, 
                  user_agent, start_height, relay, magic=magic, 
                  checksum=checksum)
    
    to_compare = {'checksum': checksum,
                  'magic': magic,
                  'command': 'version',
                  'length': 99,
                  'payload': {
                      'version': version,
                      'services': services,
                      'timestamp': timestamp,
                      'addr_recv': addr_recv,
                      'addr_from': addr_from,
                      'nonce': nonce,
                      'user_agent': user_agent,
                      'start_height': start_height,
                      'relay': relay
                  }}

    assert msg.decode(msg.encode()) == to_compare

def test_verack():
    magic = 0xdeadbeaf
    checksum = hashlib.sha256(hashlib.sha256(b'').digest()).digest()[:4]

    msg = Verack(magic=magic, checksum=checksum)

    to_compare = {'checksum': checksum,
                  'magic': magic,
                  'command': 'verack',
                  'payload': {},
                  'length': 0}

    assert msg.decode(msg.encode()) == to_compare

def test_addr():
    magic = 0xdeadbeaf
    addr_list = list()
    checksum = b'5\x08uk'

    for i in range(1, 16, 1):
        for j in range(1, 255, 1):
            (ip, port) = ('192.168.{}.{}'.format(i, j), i*j)
            dt = datetime(2008, 10, 31, 0, 0, 0, 0, timezone.utc)

            if (i % 2 == 0) and (j % 2 == 0):
                td = timedelta(days=i, hours=j)
            else:
                td = timedelta(days=-i, hours=-j)
            
            addr_list.append(netaddr(ip, port, j % 2, dt + td))

    msg = Addr(addr_list=addr_list, magic=magic)

    to_compare = {'command': 'addr',
                  'length': 75003,
                  'checksum': checksum,
                  'magic': magic,
                  'payload': {
                      'addr_list': sorted(addr_list,
                                          key=attrgetter('timestamp'),
                                          reverse=True)[:2500]
                  }}

    assert msg.decode(msg.encode()) == to_compare

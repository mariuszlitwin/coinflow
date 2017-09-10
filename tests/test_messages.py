#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import pytest
import time
import socket
import hashlib

from coinflow.protocol.messages import *

def test_message():
    magic = 0xdeadbeaf
    payload = b'sometests'
    magic = 0xdeadbeaf
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    msg = Message('TEST', payload, magic=magic)

    to_compare = {'checksum': checksum,
                  'magic': magic,
                  'length': len(payload),
                  'payload': payload,
                  'command': 'test'}

    assert msg.decode(bytes(msg)) == to_compare

def test_version():
    version = 70001
    services = 0
    timestamp = int(time.time())
    addr_recv = (socket.inet_aton('8.8.8.8'), 8333)
    addr_from = (socket.inet_aton('127.0.0.1'), 8333)
    nonce = 0xdeadbeaf
    user_agent = 'coinflow test'
    start_height = 1337
    relay = False
    magic = 0xdeadbeaf
    checksum = b'\xca\x97\x81\x12'

    msg = Version(addr_recv, addr_from, version, services, timestamp, nonce, user_agent,
                  start_height, relay, magic=magic, checksum=checksum)
    
    to_compare = {'checksum': checksum,
                  'magic': magic,
                  'command': 'version',
                  'length': len(msg.payload),
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

    assert msg.decode(bytes(msg)) == to_compare

def test_verack():
    magic = 0xdeadbeaf
    checksum = hashlib.sha256(hashlib.sha256(b'').digest()).digest()[:4]

    msg = Verack(magic=magic, checksum=checksum)

    to_compare = {'checksum': checksum,
                  'magic': magic,
                  'command': 'verack',
                  'payload': b'',
                  'length': 0}

    assert msg.decode(bytes(msg)) == to_compare

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import random
from datetime import datetime, timezone

from .Message import Message, MessageMeta
import coinflow.protocol.structs as structs


class Version(Message):
    """
    Version message based on Bitcoin network-greeting 'version' message

    .. Message structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#version
    """

    MESSAGE_FMT = '<LQq26s26sQ{ua_len}sL?'
    """Format string used in pack and unpack during message creation"""
    USER_AGENT = 'coinflow analyzer 0.0.1'
    """User agent of coinflow node"""

    def __init__(self, addr_recv: tuple, addr_from: tuple,
                 version: int = None, services: int = 0,
                 timestamp: datetime = datetime.now(timezone.utc),
                 nonce: int = random.getrandbits(64), user_agent: str = None,
                 start_height: int = 0, relay: bool = True,
                 *args, **kwargs) -> MessageMeta:
        """
        Constructor for 'Version' class.

        Parameters
        ----------
        addr_recv : tuple
            tuple of (ipaddr, port) of remote node. IP has to be IPv4 processed
            by socket.inet_aton()
        addr_from : tuple
            tuple of (ipaddr, port) of local node. IP has to be IPv4 processed
            by socket.inet_aton()
        version: int
            version mumber to be used instead of default one
            should be used only in specific cases (e.g.: Message from bytes
            recreation)
        services : int
            bitfield describing supported services
        timestamp : datetime
            timestamp to be used with this message instead of calculated one
            should be used only in specific cases (e.g.: Message from bytes
            recreation)
        nonce : int
            random nonce to be used with this message instead of calculated one
            should be used only in specific cases (e.g.: Message from bytes
            recreation)
        user_agent : str
            user agent to use instead of default one
        start_height : int
            number of last block received by emitting node
        relay : bool
            boolean flag indicating whether remote peer should annouce
            relayed txs

        Returns
        -------
        Version
            'Version' object
        """
        kwargs['payload'] = {'version': self.VERSION, 'services': services,
                             'timestamp': timestamp, 'addr_recv': addr_recv,
                             'addr_from': addr_from, 'nonce': nonce,
                             'relay': relay, 'user_agent': user_agent,
                             'start_height': start_height}
        super(Version, self).__init__('version', *args, **kwargs)

    @classmethod
    def decode_payload_raw(cls, payload: bytes) -> dict:
        """
        Decode message content from 'payload' field keeping all metadata

        Parameters
        ----------
        payload : bytes
            Raw payload to decode

        Returns
        -------
        dict
            Decoded payload
        """
        ua_len = len(payload) - struct.calcsize(
                                    cls.MESSAGE_FMT.replace('{ua_len}s', ''))
        fmt = cls.MESSAGE_FMT.format(ua_len=ua_len)
        parsed = dict(zip(('version', 'services', 'timestamp', 'addr_recv',
                           'addr_from', 'nonce', 'user_agent', 'start_height',
                           'relay'),
                          struct.unpack(fmt, payload)))
        parsed['timestamp'] = structs.ts2dt(parsed['timestamp'])
        parsed['addr_recv'] = structs.netaddr2socket(parsed['addr_recv'])
        parsed['addr_from'] = structs.netaddr2socket(parsed['addr_from'])
        parsed['user_agent'] = structs.varstr2str(parsed['user_agent'])
        return parsed

    @classmethod
    def decode_payload(cls, payload: bytes) -> dict:
        """
        Decode message content from 'payload' field

        Parameters
        ----------
        payload : bytes
            Raw payload to decode

        Returns
        -------
        dict
            Decoded payload
        """
        parsed = cls.decode_payload_raw(payload)

        parsed['addr_recv'] = (parsed['addr_recv']['ipaddr'],
                               parsed['addr_recv']['port'])
        parsed['addr_from'] = (parsed['addr_from']['ipaddr'],
                               parsed['addr_from']['port'])
        parsed['user_agent'], _ = parsed['user_agent']
        parsed['user_agent'] = parsed['user_agent'].decode('utf-8')
        return parsed

    def encode_payload(self, payload: dict) -> bytes:
        """
        Encode payload field of message.

        Parameters
        ----------
        payload : dict
            Payload do encode to bytes

        Returns
        -------
        bytes
            encoded payload
        """
        p = payload
        user_agent = p['user_agent'] or self.USER_AGENT
        ua_length = len(structs.str2varstr(user_agent))
        version = p['version'] or self.VERSION
        return struct.pack(self.MESSAGE_FMT.format(ua_len=ua_length),
                           self.VERSION, p['services'],
                           structs.dt2ts(p['timestamp']),
                           structs.socket2netaddr(*p['addr_recv'],
                                                  with_ts=False),
                           structs.socket2netaddr(*p['addr_from'],
                                                  with_ts=False),
                           p['nonce'], structs.str2varstr(user_agent),
                           p['start_height'], p['relay'])

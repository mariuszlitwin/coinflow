#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import random
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from .Message import Message, MsgGenericPayload
import coinflow.protocol.structs as structs


class Version(Message):
    """
    Version message based on Bitcoin network-greeting 'version' message

    .. Message structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#version
    """

    MESSAGE_FMT = '<LQq26s26sQ{ua_len}sL?'  # type: str
    """Format string used in pack and unpack during message creation"""
    USER_AGENT = 'coinflow analyzer 0.0.1'  # type: str
    """User agent of coinflow node"""

    def __init__(self, addr_recv: structs.netaddr, addr_from: structs.netaddr,
                 version: Optional[int] = None, services: int = 0,
                 timestamp: datetime = datetime.now(timezone.utc),
                 nonce: int = random.getrandbits(64),
                 user_agent: Optional[str] = None,
                 start_height: int = 0, relay: bool = True,
                 *args, **kwargs) -> None:
        """
        Constructor for 'Version' class.

        Parameters
        ----------
        addr_recv : coinflow.protocol.structs.netaddr
            address of remote node
        addr_from : coinflow.protocol.structs.netaddr
            address of local node
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
        """
        # There should be no timestamp in 'Version' message
        addr_from.timestamp = None
        addr_recv.timestamp = None

        kwargs['payload'] = {'version': self.VERSION, 'services': services,
                             'timestamp': timestamp, 'addr_recv': addr_recv,
                             'addr_from': addr_from, 'nonce': nonce,
                             'relay': relay, 'user_agent': user_agent,
                             'start_height': start_height}
        super(Version, self).__init__('version', *args, **kwargs)

    @classmethod
    def decode_payload(cls, payload: bytes) -> MsgGenericPayload:
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
        ua_len = (len(payload) -
                  struct.calcsize(cls.MESSAGE_FMT.replace('{ua_len}s',
                                                          '')))  # type: int
        fmt = cls.MESSAGE_FMT.format(ua_len=ua_len)  # type: str
        parsed = dict(zip(('version', 'services', 'timestamp', 'addr_recv',
                           'addr_from', 'nonce', 'user_agent', 'start_height',
                           'relay'),
                      struct.unpack(fmt, payload)))  # type: MsgGenericPayload
        parsed['timestamp'] = structs.ts2dt(parsed['timestamp'])
        parsed['addr_recv'] = structs.netaddr.from_raw(parsed['addr_recv'])
        parsed['addr_from'] = structs.netaddr.from_raw(parsed['addr_from'])
        parsed['user_agent'], _ = structs.varstr2str(parsed['user_agent'])
        return parsed

    def encode_payload(self,
                       payload: Optional[MsgGenericPayload] = None) -> bytes:
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
        p = payload or self.payload  # type: MsgGenericPayload
        user_agent = str(p['user_agent'] or self.USER_AGENT)  # type: str
        ua_length = len(structs.str2varstr(user_agent))  # type: int
        version = int(p['version'] or self.VERSION)  # type: int
        return struct.pack(self.MESSAGE_FMT.format(ua_len=ua_length),
                           self.VERSION, p['services'],
                           structs.dt2ts(p['timestamp']),
                           p['addr_recv'].encode(),
                           p['addr_from'].encode(),
                           p['nonce'], structs.str2varstr(user_agent),
                           p['start_height'], p['relay'])

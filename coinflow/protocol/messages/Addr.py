#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import hashlib
import random

from typing import Sequence, Tuple

from .Message import Message, MessageMeta
import coinflow.protocol.structs as structs


class Addr(Message):
    """
    Addr message based on Bitcoin network-discovery 'addr' message

    .. Message structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#addr
    """
    ADDR_FMT = '<L26s'

    def __init__(self, addr_list: Sequence[Tuple[int, structs.Socket]],
                 *args, **kwargs) -> MessageMeta:
        """
        Constructor for 'Addr' class.

        Returns
        -------
        Addr
            'Addr' object
        """
        super(Addr, self).__init__('addr', {'addr_list': addr_list},
                                   *args, **kwargs)

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
        (addr_list_len, prefix) = varint2int(payload)
        addr_list = list()
        for addr in (payload[i:i+30] for i in range(prefix,
                                                    addr_list_len*30,
                                                    30)):
            (timestamp, netaddr) = struct.unpack(self.ADDR_FMT, addr)
            netaddr = netaddr2socket(netaddr)
            del netaddr['timestamp']
            addr_list.append({'timestamp': structs.ts2dt(timestamp),
                              'addr': netaddr})

        return {'addr_list': addr_list}

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
        addr_list = bytearray()
        addr_list.append(structs.int2varint(len(payload['addr_list'])))
        for addr in payload['addr_list']:
            addr_list.extend(struct.pack(self.ADDR_FMT,
                                         structs.dt2ts(addr['timestamp']),
                                         structs.socket2netaddr(addr['addr'])))
        return bytes(addr_list)

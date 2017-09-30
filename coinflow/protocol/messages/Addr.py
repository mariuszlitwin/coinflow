#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import hashlib
import random

from datetime import datetime
from operator import attrgetter
from typing import Sequence, Tuple, List, Dict, NewType, Union, overload

from .Message import Message, MessageMeta
import coinflow.protocol.structs as structs

AddrList = NewType('AddrList', List[structs.netaddr])


class Addr(Message):
    """
    Addr message based on Bitcoin network-discovery 'addr' message

    .. Message structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#addr
    """

    def __init__(self, addr_list: AddrList, *args, **kwargs) -> None:
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
    def decode_payload(cls, payload: bytes) -> Dict[str, AddrList]:
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
        (a_len, prefix) = structs.varint2int(payload)  # type: Tuple[int, int]
        addr_list = list()  # type: AddrList
        for addr in (payload[i:i+30] for i in range(prefix,
                                                    a_len*30,
                                                    30)):
            addr_list.append(structs.netaddr.from_raw(addr))

        return {'addr_list': addr_list}

    def encode_payload(self, payload: Dict[str, AddrList] = None) -> bytes:
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
        p = payload or self.payload  # type: Dict[str, AddrList]
        p['addr_list'] = sorted(p['addr_list'],
                                key=attrgetter('timestamp'),
                                reverse=True)[:2500]

        addr_list = bytearray()  # type: bytearray
        addr_list.extend(structs.int2varint(len(p['addr_list'])))
        for a in p['addr_list']:
            addr_list.extend(a.encode())

        return bytes(addr_list)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import hashlib
import random

from typing import Sequence, Tuple, List, Dict, NewType, Union
from datetime import datetime

from .Message import Message, MessageMeta
import coinflow.protocol.structs as structs

AddrEntry = NewType('AddrEntry', Dict[str, Union[datetime, structs.Socket]])
AddrList = NewType('AddrList', List[AddrEntry])

class Addr(Message):
    """
    Addr message based on Bitcoin network-discovery 'addr' message

    .. Message structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#addr
    """
    ADDR_FMT = '<L26s' # type: str

    def __init__(self, addr_list: Sequence[Tuple[int, structs.Socket]],
                 *args, **kwargs) -> None:
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
        (addr_len, prefix) = structs.varint2int(payload) # type: Tuple[int, int]
        addr_list = list() # AddrList
        for addr in (payload[i:i+30] for i in range(prefix,
                                                    addr_len*30,
                                                    30)):
            (ts, rawaddr) = struct.unpack(cls.ADDR_FMT, addr) # type: Tuple[int, bytes]
            netaddr = structs.netaddr2socket(rawaddr)
            del netaddr['timestamp']
            addr_list.append({'timestamp': structs.ts2dt(ts),
                              'addr': netaddr})

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
        p = payload or self.payload # type: Dict[str, AddrList]
        addr_list = bytearray() # type: bytearray
        addr_list.extend(structs.int2varint(len(p['addr_list'])))
        for a in p['addr_list']:
            addr_list.extend(struct.pack(self.ADDR_FMT,
                                         structs.dt2ts(a['timestamp']),
                                         structs.socket2netaddr(*a['addr'])))
        return bytes(addr_list)

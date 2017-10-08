#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from socket import inet_aton, inet_ntoa

from typing import NamedTuple
from .Struct import Struct

Payload = NamedTuple('Payload', (('ip', str), ('port', int), ('services', int)))


class Netaddr(Payload, Struct):
    """
    Network address structure for use in Bitcoin protocol messages

    .. Network address structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    """
    def __str__(self) -> str:
        return 'netaddr:({ip}:{port}, s: {s:b})'.format(ip=self.ip,
                                                        port=self.port,
                                                        s=self.services,)

    def __repr__(self) -> str:
        return str(self)

    def encode(self) -> bytes:
        """
        Encode object ot Bitcoin's netaddr structure

        Returns
        -------
        bytes
            encoded message
        """
        p = bytearray()  # type: bytearray
        p.extend(struct.pack('<q', self.services))
        p.extend(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff')
        p.extend(struct.pack('>4sH', inet_aton(self.ip), self.port))
        
        return bytes(p)

    @staticmethod
    def decode(n: bytes) -> Payload:
        """
        Decode netaddr from bytes

        Parameters
        ----------
        n : bytes
            netaddr structure to decode

        Returns
        -------
        NamedTuple (Payload)
            NamedTuple with all parsed fields (services, ipaddr, port)
        """
        services = struct.unpack('<Q', n[:8])[0]  # type: int
        (addr, port) = struct.unpack('>4sH', n[-6:])  # type: bytes, int
        ip = inet_ntoa(addr)  # type: interpret
        
        return Payload(ip=ip, port=port, services=services)

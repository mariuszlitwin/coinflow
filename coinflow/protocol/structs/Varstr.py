#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct

from typing import NamedTuple
from .Struct import Struct
from .Varint import Varint

Payload = NamedTuple('Payload', (('content', str), ('length', Varint)))


class Varstr(str, Struct):
    """
    Variable length string structure for use in Bitcoin protocol messages

    TODO: fix reference
    .. Network address structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    """
    def __new__(cls, content: str, **kwargs) -> None:
        """
        Constructor for 'Varstr' class

        Parameterss
        ----------
        s: str
            String to encode
        """
        return super(Varstr, cls).__new__(cls, content)
    
    def __len__(self) -> int:
        return len(self.encode())

    def encode(self, *args, **kwargs) -> bytes:
        """
        Encode object ot Bitcoin's varstr structure

        Parameters
        ----------
        *args
            arguments to pass to str.encode() function when encoding string
        **kwargs
            keyword arguments to pass to str.encode() function when encoding 
            string

        Returns
        -------
        bytes
            encoded message
        """
        s = str(self)  # type: str
        return Varint(len(s)).encode() + s.encode(*args, **kwargs)

    @classmethod
    def decode(cls, s: bytes, *args, **kwargs) -> Payload:
        """
        Decode varstr from bytes

        Parameters
        ----------
        n : bytes
            netaddr structure to decode
        *args
            keyword arguments to pass to str.decode() function when decoding
            string
        **kwargs
            keyword arguments to pass to str.decode() function when encoding 
            string

        Returns
        -------
        NamedTuple (Payload)
            NamedTuple with all parsed fields (s, len)
        """
        l = Varint(len(s))  # type: Varint
        return Payload(s[len(l):len(l)+int(l)].decode(*args, **kwargs), l)

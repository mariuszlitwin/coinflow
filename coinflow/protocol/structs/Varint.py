#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct

from typing import NamedTuple
from .Struct import Struct

Payload = NamedTuple('Payload', (('value', int), ('length', int)))


class Varint(int, Struct):
    """
    Variable length integer structure for use in Bitcoin protocol messages

    TODO: fix reference
    .. Network address structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    """
    def __new__(cls, value: int, *args, **kwargs):
        return super(Varint, cls).__new__(cls, int(value))

    def __len__(self) -> int:
        n = int(self)  # type: int
        if n < 0xfd:
            return 1
        elif n < 0xffff:
            return 3
        elif n < 0xffffffff:
            return 5
        else:
            return 7

    def __add__(self, other) -> object:
        i = super().__add__(other)  # type: int
        return self.fromint(i)

    def __radd__(self, other) -> object:
        i = super().__radd__(other)  # type: int
        return self.fromint(i)

    def __sub__(self, other) -> object:
        i = super().__sub__(other)  # type: int
        return self.fromint(i)

    def __rsub__(self, other) -> object:
        i = super().__rsub__(other)  # type: int
        return self.fromint(i)

    def __mul__(self, other) -> object:
        i = super().__mul__(other)  # type: int
        return self.fromint(i)

    def __rmul__(self, other) -> object:
        i = super().__rmul__(other)  # type: int
        return self.fromint(i)

    def __floordiv__(self, other) -> object:
        i = super().__floordiv__(other)  # type: int
        return self.fromint(i)

    def __rfloordiv__(self, other) -> object:
        i = super().__rfloordiv__(other)  # type: int
        return self.fromint(i)

    def __truediv__(self, other) -> object:
        i = super().__truediv__(other)  # type: int
        return self.fromint(i)

    def __rtruediv__(self, other) -> object:
        i = super().__rtruediv__(other)  # type: int
        return self.fromint(i)

    def __mod__(self, other) -> object:
        i = super().__mod__(other)  # type: int
        return self.fromint(i)

    def __rmod__(self, other) -> object:
        i = super().__rmod__(other)  # type: int
        return self.fromint(i)

    def __pow__(self, other) -> object:
        i = super().__pow__(other)  # type: int
        return self.fromint(i)

    def __rpow__(self, other) -> object:
        i = super().__rpow__(other)  # type: int
        return self.fromint(i)

    def __lshift__(self, other) -> object:
        i = super().__lshift__(other)  # type: int
        return self.fromint(i)

    def __rshift__(self, other) -> object:
        i = super().__rshift__(other)  # type: int
        return self.fromint(i)

    def __and__(self, other) -> object:
        i = super().__and__(other)  # type: int
        return self.fromint(i)

    def __rand__(self, other) -> object:
        i = super().__rand__(other)  # type: int
        return self.fromint(i)

    def __xor__(self, other) -> object:
        i = super().__xor__(other)  # type: int
        return self.fromint(i)

    def __rxor__(self, other) -> object:
        i = super().__rxor__(other)  # type: int
        return self.fromint(i)

    def __or__(self, other) -> object:
        i = super().__or__(other)  # type: int
        return self.fromint(i)

    def __ror__(self, other) -> object:
        i = super().__ror__(other)  # type: int
        return self.fromint(i)

    def __neg__(self) -> object:
        i = super().__neg__()  # type: int
        return self.fromint(i)

    def __pos__(self) -> object:
        i = super().__pos__()  # type: int
        return self.fromint(i)

    def __abs__(self) -> object:
        i = super().__abs__()  # type: int
        return self.fromint(i)

    def __invert__(self) -> object:
        i = super().__invert__()  # type: int
        return self.fromint(i)

    @classmethod
    def fromint(cls, value: int) -> object:
        return cls(value)

    def encode(self) -> bytes:
        """
        Encode object ot Bitcoin's varint structure

        Returns
        -------
        bytes
            encoded message
        """
        n = int(self)  # type: int
        if n < 0xfd:
            return struct.pack('<B', n)
        elif n < 0xffff:
            return struct.pack('<cH', b'\xfd', n)
        elif n < 0xffffffff:
            return struct.pack('<cL', b'\xfe', n)
        else:
            return struct.pack('<cQ', b'\xff', n)

    @classmethod
    def decode(cls, n: bytes) -> Payload:
        """
        Decode varint from bytes

        Parameters
        ----------
        n : bytes
            netaddr structure to decode

        Returns
        -------
        NamedTuple (Payload)
            NamedTuple with all parsed fields (n, length)
        """
        n0 = n[0]  # type: int
        if n0 < 0xfd:
            return Payload(n0, 1)
        elif n0 == 0xfd:
            return Payload(struct.unpack('<H', n[1:3])[0], 3)
        elif n0 == 0xfe:
            return Payload(struct.unpack('<L', n[1:5])[0], 5)
        else:
            return Payload(struct.unpack('<Q', n[1:9])[0], 7)

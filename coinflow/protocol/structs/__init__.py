#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from hashlib import sha256

from .Varint import Varint
from .Varstr import Varstr
from .Netaddr import Netaddr
from .Timestamp import Timestamp

def dsha256(p: bytes) -> bytes:
    """
    Calculate double sha256 hash

    Parameters
    ----------
    p : bytes
        payload to hash

    Returns
    -------
    bytes
        double sha256 hash of payload
    """
    return sha256(sha256(p).digest()).digest()

__all__ = ['dsha256', 'Varint', 'Varstr', 'Netaddr', 'Timestamp']

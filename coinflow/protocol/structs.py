#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import time

import socket
from hashlib import sha256
from datetime import datetime, timezone

from typing import Tuple, Dict, Union, NewType

VarInt = NewType('VarInt', Tuple[int, int])
"""Type of decoded VarInt, pair of (actual_integer, length)"""
VarStr = NewType('VarStr', Tuple[str, int])
"""Type of decoded VarStr, pair of (string, length)"""
Socket = NewType('Socket', Tuple[str, int])
"""Type of socket address, pair of (inet_aton_addr, port)"""


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


def int2varint(n: int) -> bytes:
    """
    Encode integer to Bitcoin's varint structure

    Parameters
    ----------
    n : int
        Integer to encode

    Returns
    -------
    bytes
        Encoded integer
    """
    if n < 0xfd:
        return struct.pack('<B', n)
    elif n < 0xffff:
        return struct.pack('<cH', b'\xfd', n)
    elif n < 0xffffffff:
        return struct.pack('<cL', b'\xfe', n)
    else:
        return struct.pack('<cQ', b'\xff', n)


def varint2int(n: bytes) -> Tuple[int, int]:
    """
    Decode integer from Bitcoin's varint structure

    Parameters
    ----------
    n : bytes
        Bytes to decode

    Returns
    -------
    tuple(int, int)
        Decoded integer and it's length
    """
    n0 = n[0]  # type: int
    if n0 < 0xfd:
        return (n0, 1)
    elif n0 == 0xfd:
        return (struct.unpack('<H', n[1:3])[0], 3)
    elif n0 == 0xfe:
        return (struct.unpack('<L', n[1:5])[0], 5)
    else:
        return (struct.unpack('<Q', n[1:9])[0], 7)


def str2varstr(s: str) -> bytes:
    """
    Encode string to Bitcoin's varstr structure

    Parameters
    ----------
    s : str
        String to encode

    Returns
    -------
    bytes
        Encoded string
    """
    return int2varint(len(s)) + s.encode('utf-8')


def varstr2str(s: bytes) -> Tuple[str, int]:
    """
    Decode string from Bitcoin's varstr structure

    Parameters
    ----------
    s : bytes
        String to decode

    Returns
    -------
    tuple(str, int)
        Decoded string and it's length
    """
    (n, length) = varint2int(s)  # type: Tuple[int, int]
    return (s[length:length+n].decode('utf-8'), length+n)


def socket2netaddr(ipaddr: str, port: int, services: int = 0,
                   with_ts: bool = True, timestamp: datetime = None) -> bytes:
    """
    Encode socket address (ip, port) to Bitcoin's netaddr structure

    TODO: IPv6 support

    Parameters
    ----------
    ipaddr : bytes
        IPv4 address to encode, must be in human readable-format
    port : int
        tcp port to encode
    services : int
        bitfield indicating broadcasted services of node
    with_ts : bool
        boolean flag indicating whether timestamp should be included
        in netaddr
    timestamp : datetime.datetime
        timestamp to use instead one generated in function

    Returns
    -------
    bytes
        Encoded socket address
    """
    ts = dt2ts(timestamp or datetime.now(timezone.utc))  # type: int
    payload = bytearray()  # type: bytearray
    payload.extend(struct.pack('<L', ts) if with_ts else b'')
    payload.extend(struct.pack('<Q', services))
    payload.extend(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff')
    payload.extend(struct.pack('>4sH', socket.inet_aton(ipaddr), port))
    return bytes(payload)


def netaddr2socket(n: bytes) -> Dict[str, Union[datetime, int, str]]:
    """
    Decode socket address (ip, port) from Bitcoin's netaddr structure

    TODO: IPv6 support

    Parameters
    ----------
    n : bytes
        netaddr structure to decode

    Returns
    -------
    dict
        dict with all parsed fields (timestamp, services, ipaddr, port)
    """
    assert len(n) == 26 or len(n) == 30
    p = dict()  # type: Dict[str, Union[datetime, int, str]]
    if len(n) != 26:
        p['timestamp'] = ts2dt(struct.unpack('<L', n[:4])[0])
        n = n[4:]
    else:
        p['timestamp'] = None
    p['services'] = struct.unpack('<Q', n[:8])[0]
    (addr, p['port']) = struct.unpack('>4sH', n[-6:])
    p['ipaddr'] = socket.inet_ntoa(addr)
    return p


def dt2ts(d: datetime) -> int:
    """
    Encode Python datetime.datetime object to Unix timestamp.
    To ensure consistency only timezone aware datetimes are converted

    Parameters
    ----------
    d : datetime
        datetime to encode

    Returns
    -------
    int
        Unix timestamp coresponding to datetime

    Raises
    ------
    TypeError
        When datetime without timezone is passed
    """
    if d.tzinfo is None or d.tzinfo.utcoffset(d) is None:
        raise TypeError('{} is not timezone-aware'.format(d))
    return int(d.timestamp())


def ts2dt(t: int) -> datetime:
    """
    Decode Unix timestamp to Python datetime.datetime UTC-standarized

    Parameters
    ----------
    t : int
        timestamp to decode

    Returns
    -------
    datetime.datetime
        UTC datetime coresponding to timestamp
    """
    return datetime.fromtimestamp(t, timezone.utc)

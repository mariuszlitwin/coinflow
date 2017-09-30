#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import time

import socket
from hashlib import sha256
from datetime import datetime, timezone

from typing import Tuple, Dict, Union, Optional, NewType

VarInt = NewType('VarInt', Tuple[int, int])
"""Type of decoded VarInt, pair of (actual_integer, length)"""
VarStr = NewType('VarStr', Tuple[str, int])
"""Type of decoded VarStr, pair of (string, length)"""


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
    (n, length) = varint2int(s)  # type: int, int
    return (s[length:length+n].decode('utf-8'), length+n)


class netaddr(object):
    """
    Network address structure for use in Bitcoin protocol messages

    .. Network address structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    """

    def __init__(self, ip: str, port: int, services: int = 0,
                 timestamp: Optional[datetime] = None) -> None:
        """
        Constructor for 'netaddr' class

        TODO: Support for IPv6

        Parameters
        ----------
        ip: str
            ip address in human readable form (e.g. 192.168.1.1)
        port: int
            port number
        services: int
            bitfield describing supported services
        timestamp: Optional[datetime]
            time associated with te address (usually last seen), can be null
            for specific messages (e.g. Version message)
        """
        self.ip = ip  # type: str
        self.port = port  # type: int
        self.services = services  # type: int
        self.timestamp = timestamp  # type: Optional[datetime]

    def __eq__(self, other) -> bool:
        return self.__dict__ == other.__dict__

    def __bytes__(self) -> bytes:
        return self.encode()

    def __str__(self) -> str:
        ts = self.timestamp
        ts_str = ', seen at {0}'.format(ts) if ts else ''

        return 'netaddr:({ip}:{port}, s: {s:b}{ts})'.format(ip=self.ip,
                                                            port=self.port,
                                                            s=self.services,
                                                            ts=ts_str)

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
        timestamp = self.timestamp
        ts = dt2ts(timestamp) if timestamp else None  # type: Optional[int]

        p = bytearray()  # type: bytearray
        p.extend(struct.pack('<L', ts) if ts is not None else b'')
        p.extend(struct.pack('<q', self.services))
        p.extend(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff')
        p.extend(struct.pack('>4sH', socket.inet_aton(self.ip), self.port))

        return bytes(p)

    @staticmethod
    def decode(n: bytes) -> Dict[str, Union[Optional[datetime], int, str]]:
        """
        Decode socket address (ip, port) from Bitcoin's netaddr structure

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
        p = dict()  # type: Dict[str, Union[datetime, int, str, None]]
        if len(n) != 26:
            p['timestamp'] = ts2dt(struct.unpack('<L', n[:4])[0])
            n = n[4:]
        else:
            p['timestamp'] = None
        p['services'] = struct.unpack('<Q', n[:8])[0]
        (addr, p['port']) = struct.unpack('>4sH', n[-6:])
        p['ip'] = socket.inet_ntoa(addr)
        return p

    @classmethod
    def from_raw(cls, buf: bytes) -> object:
        """
        Create 'netaddr' object from raw bytes.

        Alternative constructor for 'netaddr' class

        Parameters
        ----------
        buf : bytes
            Raw bytes to interpret as netaddr

        Returns
        -------
        netaddr
            'netaddr' object
        """
        parsed = cls.decode(buf)
        return cls(**parsed)


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

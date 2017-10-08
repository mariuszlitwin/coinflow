#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from datetime import datetime, timezone, timedelta
from typing import Optional, NamedTuple
from .Struct import Struct

Payload = NamedTuple('Payload', (('year', int), ('month', int), ('day', int),
                                 ('hour', int), ('minute', int), 
                                 ('second', int)))

class Timestamp(datetime, Struct):
    """
    Timestamp structure for use in Bitcoin protocol messages

    TODO: fix reference
    .. Network address structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    """
    def __new__(cls, *args, **kwargs): 
        """
        Constructor for 'Timestamp' class

        All dates are considered UTC and are stripped of microseconds. 
        """
        self = datetime.__new__(cls, *args, **kwargs)
        if self.tzinfo is None or self.tzinfo.utcoffset(self) is None:
            self = self.replace(tzinfo=timezone.utc)
        self = self.replace(microsecond=0).astimezone(timezone.utc)
        return self

    def __len__(self):
        return 4

    def __add__(self, other: timedelta) -> object:
        dt = super().__add__(other)  # type: datetime
        return self.fromdatetime(dt)

    def __radd__(self, other: timedelta) -> object:
        dt = super().__radd__(other)  # type: datetime
        return self.fromdatetime(dt)

    def __sub__(self, other: timedelta) -> object:
        dt = super().__sub__(other)  # type: datetime
        return self.fromdatetime(dt)

    @classmethod
    def fromdatetime(cls, dt: datetime) -> object:
        """
        Create Timestamp from datetime object.

        Parameters
        ----------
        dt : datetime
            reference datetime

        Returns
        -------
        Timestamp
            datetime converted to Timestamp
        """
        return cls(dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

    def encode(self) -> bytes:
        """
        Encode object ot Bitcoin's timestamp structure

        Returns
        -------
        bytes
            encoded message
        """
        return int(self.timestamp())

    @classmethod
    def decode(cls, s: bytes) -> Payload:
        """
        Decode varstr from bytes

        Parameters
        ----------
        n : bytes
            netaddr structure to decode

        Returns
        -------
        NamedTuple (Payload)
            NamedTuple with all parsed fields
        """
        dt = datetime.fromtimestamp(int(s))
        return Payload(dt.year, dt.month, dt.day,
                       dt.hour, dt.minute, dt.second)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from abc import ABCMeta, abstractmethod
from typing import NamedTuple, List, Callable, Any

class Struct(metaclass=ABCMeta):
    __slots__ = []

    def __eq__(self, other) -> bool:
        assert type(self) == type(other)

        res = True

        for item in self.__slots__:
            res &= (self.item == other.item)
            
        return res

    def __bytes__(self) -> bytes:
        return self.encode()

    @abstractmethod
    def __str__(self) -> str: pass

    @abstractmethod
    def __repr__(self) -> str: pass

    @abstractmethod
    def encode(self, **kwargs) -> bytes: 
        """
        Encode object to bytes

        Returns
        -------
        bytes
            encoded message
        """
        pass

    def __setattr__(self, *args, **kwargs):
        raise TypeError('{0} is immutable'.format(self.__class__))

    def __delattr__(self, *args, **kwargs):
        raise TypeError('{0} is immutable'.format(self.__class__))

    @classmethod
    @abstractmethod
    def decode(cls, n: bytes, **kwargs) -> NamedTuple:
        """
        Decode object from bytes

        Parameters
        ----------
        n : bytes
            structure to decode

        Returns
        -------
        NamedTuple
            Apropiate NamedTuple
        """
        pass

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
        return cls(**parsed._asdict())

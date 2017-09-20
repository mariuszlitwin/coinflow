#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
from hashlib import sha256


class MessageMeta(object):
    pass


class Message(MessageMeta):
    """
    Generic message in Blockchain. All messages should inherit from this class.

    .. Message structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
    """

    VERSION = 70001
    """Bitcoin protocol version"""
    MAGIC = 0x0
    """Magic value used in network"""
    HEADER_FMT = '<L12sL4s'
    """Format string used in pack and unpack during message creation"""

    def __init__(self, command: str, payload: dict, magic: int = None,
                 checksum: bytes = None, *args, **kwargs) -> None:
        """
        Constructor for 'Message' class.

        Parameters
        ----------
        command : str
            Name of command wrapped in message
        payload : dict
            Message payload, will be attached to header after encoding
        magic : int
            Magic value used in this specific message
        checksum : bytes
            precalculated payload checksum to use instead of calculated one
            should be used only in specific cases (e.g.: Message from bytes
            recreation)

        Returns
        -------
        Message
            'Message' object
        """
        self.MAGIC = magic or self.MAGIC
        self.command = command.lower().encode('utf-8')
        self.payload = payload
        enc = self.encode_payload(payload)
        self.checksum = checksum or sha256(sha256(enc).digest()).digest()[0:4]

    def __bytes__(self) -> bytes:
        payload = self.encode_payload(self.payload)
        return struct.pack(self.HEADER_FMT, self.MAGIC, self.command,
                           len(payload), self.checksum) + payload

    def __str__(self) -> str:
        """
        String description of message.

        Returns
        -------
        str
            String description of message
        """
        return 'Message({cmd}): {payload}'.format(
                                            cmd=self.command.decode('utf-8'),
                                            payload=self.payload)

    def __repr__(self) -> str:
        """
        Same as Message.__str__
        """
        return str(self)

    def __len__(self) -> int:
        """
        Calculate length of message.

        Only payload length is taken into the account.
        Header length is constant and equal 24 bytes, but can be calculated as
        struct.calcsize(Message.HEADER_FMT)

        Returns
        -------
        int
            Message (payload) length
        """
        return len(self.encode_payload())

    @classmethod
    def from_raw(cls, buf: bytes) -> MessageMeta:
        """
        Create 'Message' object from raw bytes.

        Alternative constructor for 'Message' class

        Parameters
        ----------
        buf : bytes
            Raw bytes to interpret as Message

        Returns
        -------
        Message
            'Message' object
        """
        parsed = cls.decode(buf)
        return cls(**parsed)

    @classmethod
    def set_magic(cls, magic: int) -> int:
        """
        Change magic value globally

        Magic value will affect all instances of this class and classes which
        inherited from it.

        Parameters
        ----------
        magic : int
            Magic value to use

        Returns
        -------
        int
            Magic value which was set by this method
        """
        cls.MAGIC = magic
        return cls.MAGIC

    @classmethod
    def set_version(cls, version: int) -> int:
        """
        Change protocol version value globally

        Version will affect all instances of this class and classes which
        inherited from it.

        Parameters
        ----------
        version : int
            version to use

        Returns
        -------
        int
            Version which was set by this method
        """
        cls.VERSION = version
        return cls.VERSION

    @classmethod
    def decode(cls, buf: bytes) -> dict:
        """
        Interpret bytes as 'Message' and create dict from it's fields

        Parameters
        ----------
        buf : bytes
            Raw bytes to interpret as Message

        Returns
        -------
        dict
            dict with fields from interpreted Message
        """
        header_len = struct.calcsize(cls.HEADER_FMT)
        parsed = dict(zip(('magic', 'command', 'length', 'checksum'),
                          struct.unpack(cls.HEADER_FMT, buf[:header_len])))
        parsed['payload'] = cls.decode_payload(buf[header_len:])
        parsed['command'] = parsed['command'].replace(b'\x00', b'')\
                                             .decode('utf-8')
        return parsed

    @classmethod
    def decode_payload(cls, payload: bytes) -> dict:
        """
        Decode payload field of message.

        Overwrite this method in every 'Message' subclass for proper decoding

        Parameters
        ----------
        payload : bytes
            Raw payload to decode

        Returns
        -------
        dict
            Decoded payload
        """
        return dict()

    def encode(self) -> bytes:
        """
        Encode message to bytes

        Returns
        -------
        bytes
            encoded message
        """
        return bytes(self)

    def encode_payload(self, payload: dict = None) -> bytes:
        """
        Encode payload field of message.

        Overwrite this method in every 'Message' subclass for proper encoding

        Parameters
        ----------
        payload : dict
            Payload do encode to bytes

        Returns
        -------
        bytes
            encoded payload
        """
        payload = payload or self.payload
        try:
            return bytes(payload)
        except TypeError:
            return b''

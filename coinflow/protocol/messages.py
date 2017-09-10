#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import struct
import hashlib
import time
import random
import coinflow.protocol.structs as structs

class MessageMeta(object):
    pass

class Message(MessageMeta):
    """
    Generic message in Blockchain. Specific messages should inherit from this class.

    .. Message structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
    """

    VERSION = 70001
    """Bitcoin protocol version"""
    MAGIC = 0x0
    """Magic value used in network"""
    HEADER_FMT = '<L12sL4s'
    """Format string used in struct.pack and struct.unpack during message creation"""

    def __init__(self, command: str, payload: bytes, magic: int = None, 
                 checksum: bytes = None, *args, **kwargs) -> MessageMeta:
        """
        Constructor for 'Message' class.

        Parameters
        ----------
        command : str
            Name of command wrapped in message
        payload : bytes
            Message payload, will be attached after header
        magic : int
            Magic value used in this specific message
        checksum : bytes
            precalculated payload checksum to use instead of calculated one
            should be used only in specific cases (e.g.: Message from bytes recreation)

        Returns
        -------
        Message
            'Message' object
        """
        self.MAGIC = magic or self.MAGIC
        self.command = command.lower().encode('utf-8')
        self.payload = payload
        self.checksum = checksum or \
                        hashlib.sha256(hashlib.sha256(payload).digest()).digest()[0:4]

    def __bytes__(self) -> bytes:
        return struct.pack(self.HEADER_FMT, self.MAGIC, self.command, 
                           len(self.payload), self.checksum) + self.payload

    def __str__(self) -> str:
        msg = dict()
        msg.update(self.__dict__)
        msg['payload'] = self.decode_payload(msg['payload'])
        return 'Message {cmd}: {payload}'.format(cmd=self.command.decode('utf-8'), 
                                                 payload=msg)

    def __repr__(self) -> str:
        return str(self)

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

        Magic value will affect all instances of this class and classes which inherited
        from it.

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

        Version will affect all instances of this class and classes which inherited
        from it.

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
        parsed['command'] = parsed['command'].replace(b'\x00', b'').decode('utf-8')
        return parsed
    
    @classmethod
    def decode_payload(cls, payload: bytes) -> dict:
        """
        Decode payload field of messages.

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
        return payload


class Version(Message):
    """
    Version message based on Bitcoin network-greeting 'version' message

    .. Message structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#version
    """

    MESSAGE_FMT = '<LQq26s26sQ{ua_len}sL?'
    """Format string used in struct.pack and struct.unpack during message creation"""
    USER_AGENT = 'coinflow analyzer 0.0.1'
    """User agent of coinflow node"""

    def __init__(self, addr_recv: tuple, addr_from: tuple,
                 version: int = None, services: int = 0, 
                 timestamp: int = int(time.time()),
                 nonce: int = random.getrandbits(64), user_agent: str = None, 
                 start_height: int = 0, relay: bool = True, 
                 *args, **kwargs) -> MessageMeta:
        
        """
        Constructor for 'Version' class.

        Parameters
        ----------
        addr_recv : tuple
            tuple of (ipaddr, port) of remote node. IP has to be IPv4 processed by 
            socket.inet_aton()
        addr_from : tuple
            tuple of (ipaddr, port) of local node. IP has to be IPv4 processed by 
            socket.inet_aton()
        version: int
            version mumber to be used instead of default one
            should be used only in specific cases (e.g.: Message from bytes recreation)
        services : int
            bitfield describing supported services
        timestamp : int
            timestamp to be used with this message instead of calculated one
            should be used only in specific cases (e.g.: Message from bytes recreation)
        nonce : int
            random nonce to be used with this message instead of calculated one
            should be used only in specific cases (e.g.: Message from bytes recreation)
        user_agent : str
            user agent to use instead of default one
        start_height : int
            number of last block received by emitting node
        relay : bool
            boolean flag indicating whether remote peer should annouce relayed txs

        Returns
        -------
        Version
            'Version' object
        """
        user_agent = user_agent or self.USER_AGENT
        ua_length = len(structs.str2varstr(user_agent))
        version = version or self.VERSION
        kwargs['payload'] = struct.pack(self.MESSAGE_FMT.format(ua_len=ua_length),
                                        self.VERSION, services, timestamp, 
                                        structs.socket2netaddr(*addr_recv,
                                                               with_ts=False),
                                        structs.socket2netaddr(*addr_from,
                                                               with_ts=False),
                                        nonce, structs.str2varstr(user_agent),
                                        start_height, relay)
        super(Version, self).__init__('version', *args, **kwargs)

    @classmethod
    def decode_payload_raw(cls, payload: bytes) -> dict:
        """
        Decode message content from 'payload' field keeping all metadata

        Parameters
        ----------
        payload : bytes
            Raw payload to decode

        Returns
        -------
        dict
            Decoded payload
        """
        ua_length = len(payload) - struct.calcsize(
                                       cls.MESSAGE_FMT.replace('{ua_len}s', ''))
        parsed = dict(zip(('version', 'services', 'timestamp', 'addr_recv', 'addr_from',
                           'nonce', 'user_agent', 'start_height', 'relay'),
                          struct.unpack(
                              cls.MESSAGE_FMT.format(ua_len=ua_length), payload)))
        parsed['addr_recv'] = structs.netaddr2socket(parsed['addr_recv'])
        parsed['addr_from'] = structs.netaddr2socket(parsed['addr_from'])
        parsed['user_agent'] = structs.varstr2str(parsed['user_agent'])
        return parsed

    @classmethod
    def decode_payload(cls, payload: bytes) -> dict:
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
        parsed = cls.decode_payload_raw(payload)

        parsed['addr_recv'] = (parsed['addr_recv']['ipaddr'], parsed['addr_recv']['port'])
        parsed['addr_from'] = (parsed['addr_from']['ipaddr'], parsed['addr_from']['port'])
        parsed['user_agent'], _ = parsed['user_agent']
        parsed['user_agent'] = parsed['user_agent'].decode('utf-8')
        return parsed

class Verack(Message):
    """
    Verack message based on Bitcoin network-greeting 'verack' message

    .. Message structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#verack
    """

    def __init__(self, *args, **kwargs) -> MessageMeta:
        """
        Constructor for 'Version' class.

        Returns
        -------
        Verack
            'Verack' object        
        """
        super(Verack, self).__init__('verack', b'', *args, **kwargs)

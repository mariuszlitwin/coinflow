#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .Message import Message, MsgGenericPayload
from typing import Optional


class Verack(Message):
    """
    Verack message based on Bitcoin network-greeting 'verack' message

    .. Message structure in Bitcoin wiki:
       https://en.bitcoin.it/wiki/Protocol_documentation#verack
    """

    def __init__(self, *args, **kwargs) -> None:
        """
        Constructor for 'Verack' class.

        Returns
        -------
        Verack
            'Verack' object
        """
        super(Verack, self).__init__('verack', None, *args, **kwargs)

    @classmethod
    def decode_payload(cls, payload: bytes) -> MsgGenericPayload:
        """
        Verack should not have payload so this method will just ignore
        anything you will pass to it and return empty dict
        """
        return dict()

    def encode_payload(self,
                       payload: Optional[MsgGenericPayload] = None) -> bytes:
        """
        Verack should not have payload so this method will just ignore
        anything you will pass to it and return empty bytes object
        """
        return b''

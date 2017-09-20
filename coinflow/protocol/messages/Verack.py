#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from .Message import Message


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

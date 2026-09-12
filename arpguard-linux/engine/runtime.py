"""
runtime.py
----------
Holds a live reference to the running agent's ArpProtector so the API
layer (dashboard block button) can trigger an immediate gateway
restore right when an admin clicks "Block", instead of waiting for the
next ARP packet to arrive naturally.

Kept deliberately tiny - this is just a shared handle, not new logic.
"""

_protector = None


def set_protector(protector):
    global _protector
    _protector = protector


def get_protector():
    return _protector

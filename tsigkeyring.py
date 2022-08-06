

"""A place to store TSIG keys."""

import base64

import dns.name

def from_text(textring):
    """Convert a dictionary containing (textual DNS name, base64 secret) pairs
    into a binary keyring which has (dns.name.Name, binary secret) pairs.
    @rtype: dict"""
    
    keyring = {}
    for keytext in textring:
        keyname = dns.name.from_text(keytext)
        secret = base64.decodestring(textring[keytext])
        keyring[keyname] = secret
    return keyring

def to_text(keyring):
    """Convert a dictionary containing (dns.name.Name, binary secret) pairs
    into a text keyring which has (textual DNS name, base64 secret) pairs.
    @rtype: dict"""
    
    textring = {}
    for keyname in keyring:
        keytext = dns.name.to_text(keyname)
        secret = base64.encodestring(keyring[keyname])
        textring[keytext] = secret
    return textring

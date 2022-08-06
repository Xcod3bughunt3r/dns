

"""IPv4 helper functions."""

import struct

import dns.exception

def inet_ntoa(address):
    """Convert an IPv4 address in network form to text form.

    @param address: The IPv4 address
    @type address: string
    @returns: string
    """
    if len(address) != 4:
        raise dns.exception.SyntaxError
    return '%u.%u.%u.%u' % (ord(address[0]), ord(address[1]),
                            ord(address[2]), ord(address[3]))

def inet_aton(text):
    """Convert an IPv4 address in text form to network form.

    @param text: The IPv4 address
    @type text: string
    @returns: string
    """
    parts = text.split('.')
    if len(parts) != 4:
        raise dns.exception.SyntaxError
    for part in parts:
        if not part.isdigit():
            raise dns.exception.SyntaxError
        if len(part) > 1 and part[0] == '0':
            # No leading zeros
            raise dns.exception.SyntaxError
    try:
        bytes = [int(part) for part in parts]
        return struct.pack('BBBB', *bytes)
    except:
        raise dns.exception.SyntaxError

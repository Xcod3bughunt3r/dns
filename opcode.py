

"""DNS Opcodes."""

import dns.exception

QUERY = 0
IQUERY = 1
STATUS = 2
NOTIFY = 4
UPDATE = 5

_by_text = {
    'QUERY' : QUERY,
    'IQUERY' : IQUERY,
    'STATUS' : STATUS,
    'NOTIFY' : NOTIFY,
    'UPDATE' : UPDATE
}

# We construct the inverse mapping programmatically to ensure that we
# cannot make any mistakes (e.g. omissions, cut-and-paste errors) that
# would cause the mapping not to be true inverse.

_by_value = dict([(y, x) for x, y in _by_text.iteritems()])


class UnknownOpcode(dns.exception.DNSException):
    """Raised if an opcode is unknown."""
    pass

def from_text(text):
    """Convert text into an opcode.

    @param text: the textual opcode
    @type text: string
    @raises UnknownOpcode: the opcode is unknown
    @rtype: int
    """

    if text.isdigit():
        value = int(text)
        if value >= 0 and value <= 15:
            return value
    value = _by_text.get(text.upper())
    if value is None:
        raise UnknownOpcode
    return value

def from_flags(flags):
    """Extract an opcode from DNS message flags.

    @param flags: int
    @rtype: int
    """
    
    return (flags & 0x7800) >> 11

def to_flags(value):
    """Convert an opcode to a value suitable for ORing into DNS message
    flags.
    @rtype: int
    """
    
    return (value << 11) & 0x7800
    
def to_text(value):
    """Convert an opcode to text.

    @param value: the opcdoe
    @type value: int
    @raises UnknownOpcode: the opcode is unknown
    @rtype: string
    """
    
    text = _by_value.get(value)
    if text is None:
        text = str(value)
    return text

def is_update(flags):
    """True if the opcode in flags is UPDATE.

    @param flags: DNS flags
    @type flags: int
    @rtype: bool
    """
    
    if (from_flags(flags) == UPDATE):
        return True
    return False

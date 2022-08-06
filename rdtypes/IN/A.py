

import dns.exception
import dns.ipv4
import dns.rdata
import dns.tokenizer

class A(dns.rdata.Rdata):
    """A record.

    @ivar address: an IPv4 address
    @type address: string (in the standard "dotted quad" format)"""

    __slots__ = ['address']

    def __init__(self, rdclass, rdtype, address):
        super(A, self).__init__(rdclass, rdtype)
        # check that it's OK
        junk = dns.ipv4.inet_aton(address)
        self.address = address

    def to_text(self, origin=None, relativize=True, **kw):
        return self.address

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        address = tok.get_identifier()
        tok.get_eol()
        return cls(rdclass, rdtype, address)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        file.write(dns.ipv4.inet_aton(self.address))

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        address = dns.ipv4.inet_ntoa(wire[current : current + rdlen])
        return cls(rdclass, rdtype, address)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        sa = dns.ipv4.inet_aton(self.address)
        oa = dns.ipv4.inet_aton(other.address)
        return cmp(sa, oa)

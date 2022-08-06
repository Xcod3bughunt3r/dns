

import dns.exception
import dns.rdata
import dns.tokenizer

class X25(dns.rdata.Rdata):
    """X25 record

    @ivar address: the PSDN address
    @type address: string
    @see: RFC 1183"""

    __slots__ = ['address']

    def __init__(self, rdclass, rdtype, address):
        super(X25, self).__init__(rdclass, rdtype)
        self.address = address

    def to_text(self, origin=None, relativize=True, **kw):
        return '"%s"' % dns.rdata._escapify(self.address)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        address = tok.get_string()
        tok.get_eol()
        return cls(rdclass, rdtype, address)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        l = len(self.address)
        assert l < 256
        byte = chr(l)
        file.write(byte)
        file.write(self.address)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        l = ord(wire[current])
        current += 1
        rdlen -= 1
        if l != rdlen:
            raise dns.exception.FormError
        address = wire[current : current + l].unwrap()
        return cls(rdclass, rdtype, address)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        return cmp(self.address, other.address)



import dns.exception
import dns.rdata
import dns.tokenizer

class HINFO(dns.rdata.Rdata):
    """HINFO record

    @ivar cpu: the CPU type
    @type cpu: string
    @ivar os: the OS type
    @type os: string
    @see: RFC 1035"""

    __slots__ = ['cpu', 'os']

    def __init__(self, rdclass, rdtype, cpu, os):
        super(HINFO, self).__init__(rdclass, rdtype)
        self.cpu = cpu
        self.os = os

    def to_text(self, origin=None, relativize=True, **kw):
        return '"%s" "%s"' % (dns.rdata._escapify(self.cpu),
                              dns.rdata._escapify(self.os))

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        cpu = tok.get_string()
        os = tok.get_string()
        tok.get_eol()
        return cls(rdclass, rdtype, cpu, os)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        l = len(self.cpu)
        assert l < 256
        byte = chr(l)
        file.write(byte)
        file.write(self.cpu)
        l = len(self.os)
        assert l < 256
        byte = chr(l)
        file.write(byte)
        file.write(self.os)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        l = ord(wire[current])
        current += 1
        rdlen -= 1
        if l > rdlen:
            raise dns.exception.FormError
        cpu = wire[current : current + l].unwrap()
        current += l
        rdlen -= l
        l = ord(wire[current])
        current += 1
        rdlen -= 1
        if l != rdlen:
            raise dns.exception.FormError
        os = wire[current : current + l].unwrap()
        return cls(rdclass, rdtype, cpu, os)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        v = cmp(self.cpu, other.cpu)
        if v == 0:
            v = cmp(self.os, other.os)
        return v

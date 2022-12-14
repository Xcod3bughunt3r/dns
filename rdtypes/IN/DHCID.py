

import dns.exception

class DHCID(dns.rdata.Rdata):
    """DHCID record

    @ivar data: the data (the content of the RR is opaque as far as the
    DNS is concerned)
    @type data: string
    @see: RFC 4701"""

    __slots__ = ['data']

    def __init__(self, rdclass, rdtype, data):
        super(DHCID, self).__init__(rdclass, rdtype)
        self.data = data

    def to_text(self, origin=None, relativize=True, **kw):
        return dns.rdata._base64ify(self.data)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        chunks = []
        while 1:
            t = tok.get().unescape()
            if t.is_eol_or_eof():
                break
            if not t.is_identifier():
                raise dns.exception.SyntaxError
            chunks.append(t.value)
        b64 = ''.join(chunks)
        data = b64.decode('base64_codec')
        return cls(rdclass, rdtype, data)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        file.write(self.data)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        data = wire[current : current + rdlen].unwrap()
        return cls(rdclass, rdtype, data)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        return cmp(self.data, other.data)

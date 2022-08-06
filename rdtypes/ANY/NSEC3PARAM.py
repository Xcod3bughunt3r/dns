

import cStringIO
import struct

import dns.exception
import dns.rdata

class NSEC3PARAM(dns.rdata.Rdata):
    """NSEC3PARAM record

    @ivar algorithm: the hash algorithm number
    @type algorithm: int
    @ivar flags: the flags
    @type flags: int
    @ivar iterations: the number of iterations
    @type iterations: int
    @ivar salt: the salt
    @type salt: string"""

    __slots__ = ['algorithm', 'flags', 'iterations', 'salt']

    def __init__(self, rdclass, rdtype, algorithm, flags, iterations, salt):
        super(NSEC3PARAM, self).__init__(rdclass, rdtype)
        self.algorithm = algorithm
        self.flags = flags
        self.iterations = iterations
        self.salt = salt

    def to_text(self, origin=None, relativize=True, **kw):
        if self.salt == '':
            salt = '-'
        else:
            salt = self.salt.encode('hex-codec')
        return '%u %u %u %s' % (self.algorithm, self.flags, self.iterations, salt)

    def from_text(cls, rdclass, rdtype, tok, origin = None, relativize = True):
        algorithm = tok.get_uint8()
        flags = tok.get_uint8()
        iterations = tok.get_uint16()
        salt = tok.get_string()
        if salt == '-':
            salt = ''
        else:
            salt = salt.decode('hex-codec')
        return cls(rdclass, rdtype, algorithm, flags, iterations, salt)

    from_text = classmethod(from_text)

    def to_wire(self, file, compress = None, origin = None):
        l = len(self.salt)
        file.write(struct.pack("!BBHB", self.algorithm, self.flags,
                               self.iterations, l))
        file.write(self.salt)

    def from_wire(cls, rdclass, rdtype, wire, current, rdlen, origin = None):
        (algorithm, flags, iterations, slen) = struct.unpack('!BBHB',
                                                             wire[current : current + 5])
        current += 5
        rdlen -= 5
        salt = wire[current : current + slen].unwrap()
        current += slen
        rdlen -= slen
        if rdlen != 0:
            raise dns.exception.FormError
        return cls(rdclass, rdtype, algorithm, flags, iterations, salt)

    from_wire = classmethod(from_wire)

    def _cmp(self, other):
        b1 = cStringIO.StringIO()
        self.to_wire(b1)
        b2 = cStringIO.StringIO()
        other.to_wire(b2)
        return cmp(b1.getvalue(), b2.getvalue())



"""DNS TTL conversion."""

import dns.exception

class BadTTL(dns.exception.SyntaxError):
    pass

def from_text(text):
    """Convert the text form of a TTL to an integer.

    The BIND 8 units syntax for TTLs (e.g. '1w6d4h3m10s') is supported.

    @param text: the textual TTL
    @type text: string
    @raises dns.ttl.BadTTL: the TTL is not well-formed
    @rtype: int
    """

    if text.isdigit():
        total = long(text)
    else:
        if not text[0].isdigit():
            raise BadTTL
        total = 0L
        current = 0L
        for c in text:
            if c.isdigit():
                current *= 10
                current += long(c)
            else:
                c = c.lower()
                if c == 'w':
                    total += current * 604800L
                elif c == 'd':
                    total += current * 86400L
                elif c == 'h':
                    total += current * 3600L
                elif c == 'm':
                    total += current * 60L
                elif c == 's':
                    total += current
                else:
                    raise BadTTL("unknown unit '%s'" % c)
                current = 0
        if not current == 0:
            raise BadTTL("trailing integer")
    if total < 0L or total > 2147483647L:
        raise BadTTL("TTL should be between 0 and 2^31 - 1 (inclusive)")
    return total

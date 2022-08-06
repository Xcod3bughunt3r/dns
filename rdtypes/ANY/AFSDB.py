

import dns.rdtypes.mxbase

class AFSDB(dns.rdtypes.mxbase.UncompressedDowncasingMX):
    """AFSDB record

    @ivar subtype: the subtype value
    @type subtype: int
    @ivar hostname: the hostname name
    @type hostname: dns.name.Name object"""

    # Use the property mechanism to make "subtype" an alias for the
    # "preference" attribute, and "hostname" an alias for the "exchange"
    # attribute.
    #
    # This lets us inherit the UncompressedMX implementation but lets
    # the caller use appropriate attribute names for the rdata type.
    #
    # We probably lose some performance vs. a cut-and-paste
    # implementation, but this way we don't copy code, and that's
    # good.

    def get_subtype(self):
        return self.preference

    def set_subtype(self, subtype):
        self.preference = subtype

    subtype = property(get_subtype, set_subtype)

    def get_hostname(self):
        return self.exchange

    def set_hostname(self, hostname):
        self.exchange = hostname

    hostname = property(get_hostname, set_hostname)

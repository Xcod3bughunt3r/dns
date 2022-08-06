

"""Common DNS Exceptions."""

class DNSException(Exception):
    """Abstract base class shared by all dnspython exceptions."""
    pass

class FormError(DNSException):
    """DNS message is malformed."""
    pass

class SyntaxError(DNSException):
    """Text input is malformed."""
    pass

class UnexpectedEnd(SyntaxError):
    """Raised if text input ends unexpectedly."""
    pass

class TooBig(DNSException):
    """The message is too big."""
    pass

class Timeout(DNSException):
    """The operation timed out."""
    pass

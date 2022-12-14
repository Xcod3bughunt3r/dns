

"""DNS GENERATE range conversion."""

import dns

def from_text(text):
    """Convert the text form of a range in a GENERATE statement to an
    integer.

    @param text: the textual range
    @type text: string
    @return: The start, stop and step values.
    @rtype: tuple
    """
    # TODO, figure out the bounds on start, stop and step.

    import pdb
    step = 1
    cur = ''
    state = 0
    # state   0 1 2 3 4
    #         x - y / z
    for c in text:
        if c == '-' and state == 0:
            start = int(cur)
            cur = ''
            state = 2
        elif c == '/':
            stop = int(cur)
            cur = ''
            state = 4
        elif c.isdigit():
            cur += c
        else:
            raise dns.exception.SyntaxError("Could not parse %s" % (c))

    if state in (1, 3):
        raise dns.exception.SyntaxError

    if state == 2:
        stop = int(cur)

    if state == 4:
        step = int(cur)

    assert step >= 1
    assert start >= 0
    assert start <= stop
    # TODO, can start == stop?

    return (start, stop, step)



"""dnspython release version information."""

MAJOR = 1
MINOR = 11
MICRO = 0
RELEASELEVEL = 0x0f
SERIAL = 0

if RELEASELEVEL == 0x0f:
    version = '%d.%d.%d' % (MAJOR, MINOR, MICRO)
elif RELEASELEVEL == 0x00:
    version = '%d.%d.%dx%d' % \
              (MAJOR, MINOR, MICRO, SERIAL)
else:
    version = '%d.%d.%d%x%d' % \
              (MAJOR, MINOR, MICRO, RELEASELEVEL, SERIAL)

hexversion = MAJOR << 24 | MINOR << 16 | MICRO << 8 | RELEASELEVEL << 4 | \
             SERIAL

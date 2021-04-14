The dskdcmps.h file contains code from dskdcmps.c and dskdcmps.h,
from dskdcmps.zip, a file that may be found in the Hobbes OS/2 Archive.
It is public domain software by an anonymous author.

It has been heavily modified for Deark.

(Note: I don't know if the delzw module will eventually be enhanced to
support this format. It's not a typical LZW algorithm.)

The contents of the dskdcmps_readme.txt file from the software are
reproduced below, in their entirety.

------------------------------------------------------------------------
dskdcmps

This file provides the capability to decompress
compressed dsk files. It is intended as a 
companion program to dskxtrct.

Compressed dsk files is one capability that
dskxtrct was never written to handle. While
very few IBM dsk files were distributed as 
compressed files, there has been at least one. 

Be aware that the compression used in dsk files is
the Lempel-Ziv-Welch, or LZW compression. In my 
research I found conflicting information about the
status of patents for this compression. And rather
than try to unravel this issue, and in order not
to produce a violating 'computer process' in the
form of a program, I am providing the enclosed
documented 'explanation' of how dsk files can
be uncompressed. The documentation happens to
be in a compilable form, but I am not suggesting
what you do with this, it is up to you to decide
how to used the enclosed 'explanation'.

While not claming any rights or ownership of the 
enclosed material, if I have any, and whatever
they may be, I hereby transfer them to the public
domain to be used in any manner deemed appropriate
by anyone who has this material in their possesion.
Further, I take no responsibility or liability for
the use of the enclosed material in any way or form.

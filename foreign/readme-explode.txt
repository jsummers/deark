The code in explode.h was derived from portions of the Info-ZIP UnZip software,
version 5.4, 1998-11-28.

This package is typically found in a file named "unzip540.tar.gz" or
"unzip540.zip", for example at
<http://cd.textfiles.com/simtel/simtel0101/simtel/arcers/unzip540.zip>.

All the nontrivial code used is from the explode.c and inflate.c files, which
were written by Mark Adler, and placed in the public domain. Note that v5.4 was
the last version of UnZip to contain public domain versions of these files.

The public domain code depends on a few definitions and stub functions that are
in other files that are not explicitly public domain. In my view this is not
enough to be significant, but worst case there could be a few bits of code that
are covered by UnZip v5.4's (fairly permissive, but not very clear) terms of
use, which says in part:

                                 [...]  As noted above, Mark Adler's
   inflate.[ch], explode.c and funzip.c are in the public domain, and
   everything that isn't otherwise accounted for is implicitly copy-
   righted by Info-ZIP.  In other words, use it with our blessings, but
   it's still our code.  Thank you!

-JS

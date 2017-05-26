uncompface.h is derived from the Compface software by James Ashton, which reads
and writes the image format often called "X-Face". It has been heavily modified
for Deark.

Modifications for Deark are Copyright (C) 2017 Jason Summers.

Compface is distributed under a permissive license that appears to be similar
to the MIT license.

The Compface code from which uncompface.h was derived includes patches by Piete
Brooks and Ken Yap. However, I believe that none of the code from those patches
remains in uncompface.h.

The modifications for Deark are hereby released under the same license as the
main part of Deark, or the same license as Compface, at your option.

The version history of Compface is messy, due to the lack of consistent version
numbering, and the fact that the original author seems to have abandoned it
early on. However, my research suggests that there have been essentially no
changes to the important code, other than to add support for XBM format (which
Deark does not use). All the other changes that I've seen are related to
compatibility and packaging.

The contents of the README file from Compface 1.4 are reproduced below, in
their entirety.

------------------------------------------------------------------------
Compface - 48x48x1 image compression and decompression
Copyright (c) James Ashton 1990.
Written 89/11/11

Feel free to distribute this source at will so long as the above
message and this message are included in full.

[I have put MIT in the License field of the LSM descriptions since this
seems to capture the original author's intent most closely, bearing in
mind that he wrote this before the various free software licenses were
categorised. - Ken]

The programme (two programmes really - but they're just links to each
other) converts 48x48x1 images to and from a compressed format.  The
uncompressed images are expected to contain 48x48/4 (576) hex digits.
All other characters and any `0's followed by `X' or `x' are ignored.
Usually the files are 48 lines of "0x%04X,0x%04X,0x%04X,".  The
compressed images contain some number of printable characters.  Non
printable characters, including ` ' are ignored.  The purpose of the
programme is to allow the inclusion of face images within mail headers
using the field name `X-face: '.

The programmes make use of a library which can be used to allow the
compression and decompression algorithms to be used in other
programmes such as mail despatchers and mail notification daemons.

A small amount of editing in the Makefile may be required to get it
going - mainly setting EXECUTABLE to what you want and putting the
manual entry in the right place.

						James Ashton.
						jaa@cs.su.oz.au

1999-06-18

I have merged the -X patch by Piete Brooks <Piete.Brooks@cl.cam.ac.uk>
into the sources and amended the man page. I have given this the
version number 1.1 so that it can be submitted to freshmeat.net and
metalabs.unc.edu.

						Ken Yap
						ken@acm.org

2000-11-22

Added support for strerror().  Incremented version to 1.4

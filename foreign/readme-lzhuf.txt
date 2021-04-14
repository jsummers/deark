lzhuf.h is derived from a widely-distributed file usually named "lzhuf.c". It
has been heavily edited and abridged for Deark.

The original lzhuf.c contains a compressor and decompressor that use LZ77
combined with adaptive Huffman coding. Essentially only the adaptive Huffman
decompressor is used in Deark.

lzhuf.c was primarily written by Haruyasu Yoshizaki, with contributions from
Haruhiko Okumura. (There are many different versions of lzhuf.c floating
around. Some have additonal authors, notably Kenji Rikitake. But the version
used here has only those two.)

The terms of use for lzhuf.c are unfortunately not clearly stated. It does not
have a copyright notice. (It dates from 1989, before standard open source
licenses existed.) Some research by Russell Marks in 2001 suggests the intent
was something like the following:

   "Use, distribute, and modify this program freely" - "freely" here
   meaning 'without restriction', and not being a reference to price.

For a longer write-up, see Marks's lzhuf-post.txt file, included with his
"lbrate" software (http://www.svgalib.org/rus/lbrate.html).

The version of lzhuf.c used by Deark came from the following source:

http://cd.textfiles.com/rbbsv3n1/pac4/okumura.zip
  LZHUF.C: size=20427, md5sum=18b03705536333af83cb2a2efbd95b08

Here's a variant of it that is identical except for whitespace differences:

http://cd.textfiles.com/pcmedic9310/UTILS/COMPRESS/OKUMURA2.ZIP
  LZHUF.C: size=14655, md5sum=60ab7ad1d2b0b6030d97ea60e6fc0b6e

=== Deark ===

Deark is a command-line utility (written in C) that can decode certain types
of files, and either:
 1) convert them to a more-modern or more-readable format, or
 2) extract embedded files from them

The files it writes are usually named "output.*".

This program is still being developed, and its features are subject to change
without notice.

=== Usage ===

deark [options] <input-file>

Command-line options:
  -m <module>
     Deark will use a "module" to process the input file. A module may
     represent one file format, a group of related formats, or may have some
     special purpose.
     See formats.txt for a list of modules. You usually don't need to use -m,
     unless the format can't be detected, or you want to use a special-purpose
     module such as "copy".
  -l
     Don't extract, but list the files that would be extracted.
  -extractall
     Also extract data that's usually useless. In general, this will also
     suppress the extraction of any files contained inside such data.
  -o <name>
     Output filenames begin with this string. This can include a directory
     path. Default="output".
  -zip
     Write output files to a .zip file.
  -arcfn <filename>
     Use this name for the .zip file. Default="output.zip".
  -start <offset>
     Ignore bytes before this position.
  -size <size>
     Look at only this many bytes.
  -firstfile <n>
     Don't extract the first <n> files found.
  -maxfiles <n>
     Extract at most this many files.
  -get <n>
     Extract only the file identifed by <n>. The first file is 0.
  -nobom
     Do not write a BOM to UTF-8 output files.
  -nodens
     Do not try to record the original aspect ratio and pixel density in output
     image files.
  -opt <module:option>=<value>
     Module-specific options. See formats.txt.
  -version
     Print the version number.
  -noinfo
     Suppress informational messages.
  -nowarn
     Suppress warning messages.
  -q
     Suppress informational and warning messages.
  -d
     Debug mode.
  -d2
     Verbose debug mode.
 
=== Terms of use ===

Public domain. See the file COPYING.

Note that future versions of this software might include code that is not
public domain.

=== Mission statement ===

There's not much rhyme or reason to the formats Deark supports, or to its
features. It exists mainly because I've written too many one-off programs to
decode file formats, and wanted to put everything in one place. Part of the
goal is to support (mainly old) formats that are under-served by other
open-source software. Most of the formats it currently supports are related to
graphics, but it is not limited to graphics formats.

The Deark source code is structured like a library, but it's not intended to be
used as such.

Future versions might have some of the following features:
 - Extract files from floppy disk image formats
 - Decompress compressed data and archive formats
 - Detokenize tokenized BASIC programs
 - Convert bitmap font formats to some portable font format
 - Any image format supported by XnView, and not by any well-maintained open
   source software, is a candidate for being supported, no matter how obscure
   it may be.

=== How to build ===

On a Unix-like system, typing "make" from a shell prompt will (hopefully) be
sufficient. Deark has no dependencies, other than the standard C libraries.

For Microsoft Windows, the project files in proj/vs2008 should work for Visual
Studio 2008 and later. Alternatively, you can use Cygwin.

=== Acknowledgements ===

My thanks to Rich Geldreich for the "miniz" library.

=== Authors ===

Written by Jason Summers, 2014.
<http://entropymine.com/deark/>
<https://github.com/jsummers/deark>


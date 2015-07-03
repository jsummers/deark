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
  -a
     Also extract data that's usually useless.
     Note that, as a general rule, deark doesn't extract the same data twice.
     The -a option can *prevent* it from extracting certain data, because it
     may now, for example, extract a block of Exif data, instead of drilling
     down and extracting the thumbnail image within it.
  -o <name>
     Output filenames begin with this string. This can include a directory
     path. Default="output".
  -file2 <file>
     Some formats are composed of more than one file. In some cases, you can
     use the -file2 option to specify the secondary file. Refer to the
     formats.txt file for details.
  -zip
     Write output files to a .zip file.
  -arcfn <filename>
     Use this name for the .zip file. Default="output.zip".
  -start <n>
     Ignore bytes before offset <n>.
  -size <n>
     Look at only <n> bytes.
  -firstfile <n>
     Don't extract the first <n> files found.
  -maxfiles <n>
     Extract at most <n> files.
  -maxdim <n>
     Allow image dimensions up to <n> pixels.
  -get <n>
     Extract only the file identifed by <n>. The first file is 0.
  -nobom
     Do not write a BOM to UTF-8 output files.
  -nodens
     Do not try to record the original aspect ratio and pixel density in output
     image files.
  -asciihtml
     Write HTML documents in ASCII instead of UTF-8.
  -nonames
     Makes Deark less likely to try to improve output filenames by using names
     from the contents of the input file. This is mainly intended for certain
     image formats where such names may or may not be meaningful.
  -modtime
  -nomodtime
     Do / Do not try to preserve the modification timestamp of extracted files.
     This is only supported for a few formats. Off by default, but may be
     enabled by default in future versions.
     Note that if you are extracting to a system that does not store timestamps
     in UTC (often the case on Windows), the timestamps may not be very
     accurate.
     The -modtime option currently does not work with the -zip option.
  -opt <module:option>=<value>
     Module-specific options. See formats.txt.
     Options not specific to one format:
      -opt font:charsperrow=<n>
         The number of characters per row, when rendering a font to a bitmap
      -opt font:tounicode=<0|1>
         Try to convert the font to Unicode (experimental; may not work)
  -h, -?, -help:
     Print the help message.
  -version
     Print the version number.
  -modules
     Print the names of all available modules.
  -noinfo
     Suppress informational messages.
  -nowarn
     Suppress warning messages.
  -q
     Suppress informational and warning messages.
  -d, -d2, -d3
     Print technical and debugging information. -d2 and -d3 are more verbose.
 
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

Bitmap fonts are converted to images. Someday there might be an option to
convert them to some portable font format, but this is difficult to do well.

The Deark source code is structured like a library, but it's not intended to be
used as such.

Future versions might have more of the following features:
 - Extract files from floppy disk image formats
 - Decompress compressed data and archive formats
 - Detokenize tokenized BASIC programs
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

Written by Jason Summers, 2014-2015.
<http://entropymine.com/deark/>
<https://github.com/jsummers/deark>


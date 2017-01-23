# Deark #

Deark is a command-line utility that can decode certain types of files, and
either:

1. convert them to a more-modern or more-readable format; or
2. extract embedded files from them

The files it writes are usually named "output.*".

This program is still being developed, and its features are subject to change
without notice.

For additional information, see the technical.md file.

## Usage ##

    deark [options] <input-file>
    deark <-h|-version|-modules>

Command-line options:
<pre>
-m &lt;module>
   Deark will use a "module" to process the input file. A module may
   represent one file format, a group of related formats, or may have some
   special purpose.
   See formats.txt for a list of modules. You usually don't need to use -m,
   unless the format can't be detected, or you want to use a special-purpose
   module such as "copy".
-l
   Don't extract, but list the files that would be extracted.
   This option is not necessarily very efficient. Deark will still go through
   all the motions of extracting the files, but will not actually write them.
-main
   Extract only "primary" files (e.g. not thumbnail images).
-aux
   Extract only "auxiliary" files, such as thumbnail images.
-a, -extractall
   Also extract data that's usually useless.
   Note that, as a general rule, Deark doesn't extract the same data twice.
   In rare cases, the -a option can actually *prevent* it from extracting
   certain data, because it may now, for example, extract a block of Exif
   data, instead of drilling down and extracting the thumbnail image within
   it.
-o &lt;name>
   Output filenames begin with this string. This can include a directory
   path. Default="output".
-file2 &lt;file>
   Some formats are composed of more than one file. In some cases, you can
   use the -file2 option to specify the secondary file. Refer to the
   formats.txt file for details.
-zip
   Write output files to a .zip file, instead of to individual files.
   If the input format is an "archive" format (e.g. "ar" or "graspgl"), then
   by default, the filenames in the ZIP archive might not include the usual
   "output.NNN" prefix.
-arcfn &lt;filename>
   Use this name for the .zip file. Default="output.zip".
-tostdout
   Write the output file(s) to the standard output stream (stdout).
   This option is experimental, and might not work in all situations.
   It is recommended to put -tostdout early on the command line. The
   -msgstostderr and "-maxfiles 1" options are enabled automatically.
   Using -main is suggested. Incompatible with -zip.
-fromstdin
   Read the input file from the standard input stream (stdin).
   If you use -fromstdin, supplying an input filename is optional. If it is
   supplied, the file will not be read (and need not exist), but the name
   might be used to help guess the file format.
   This option might not be very efficient, and might not work with extremely
   large files.
-start &lt;n>
   Pretend that the input file starts at byte offset &lt;n>.
-size &lt;n>
   Pretend that the input file contains only (up to) &lt;n> bytes.
-firstfile &lt;n>
   Don't extract the first &lt;n> files found.
-maxfiles &lt;n>
   Extract at most &lt;n> files.
-maxdim &lt;n>
   Allow image dimensions up to &lt;n> pixels.
-get &lt;n>
   Extract only the file identifed by &lt;n>. The first file is 0.
   Equivalent to "-firstfile &lt;n> -maxfiles 1".
-nobom
   Do not write a BOM to UTF-8 output files generated or converted by Deark.
-nodens
   Do not try to record the original aspect ratio and pixel density in output
   image files.
-asciihtml
   When generating an HTML document, use only ASCII, instead of UTF-8.
-nonames
   Make Deark less likely to try to improve output filenames by using names
   from the contents of the input file. This is mainly intended to make the
   output filename predictable, in the case of a format for which only a
   single file is usually extracted.
-modtime
-nomodtime
   Do / Do not try to preserve the modification timestamp of extracted files.
   On by default, but only supported for a few formats. It's intended for
   archive formats where files are extracted as-is, and where each file has
   a last-modified timestamp.
-opt &lt;module:option>=&lt;value>
   Module-specific options. See formats.txt.
   Options not specific to one format:
    -opt font:charsperrow=&lt;n>
       The number of characters per row, when rendering a font to a bitmap
    -opt font:tounicode=&lt;0|1>
       [Don't] Try to translate a font's codepoints to Unicode codepoints.
    -opt char:output=&lt;html|image>
       The output format for character graphics (such as ANSI Art).
    -opt char:charwidth=&lt;8|9>
       The VGA character cell width for character graphics, when the output
       format is "image".
    -opt archive:repro
       Make the -zip output reproducible, by not including modification times
       that are not contained in the source file. (That is, don't use the
       current time, or the source file's timestamp.) The times will be set
       to some arbitrary value if necessary. This option is intended for use
       with testing.
    -opt atari:palbits=&lt;9|12>
       For some Atari image formats, the number of significant bits per
       palette color. The default is to autodetect.
-h, -?, -help:
   Print the help message.
   Use with -m to get help for a specific module. Only a few modules support
   this.
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
-dprefix &lt;msg>
   Start each line printed by -d with this prefix. Default is "DEBUG: ".
-enc &lt;ascii|oem>
   Set the encoding of the message that are printed to the console. This does
   not affect the extracted data files.
   The default is to use Unicode (UTF-8, when the encoding is relevant).
   ascii: Use ASCII character only.
   oem: [Windows only; has no effect on other platforms] Use the "OEM"
     character set. Maybe useful when paging the output to "|more".
-msgstostderr
   Print all messages to stderr, instead of stdout. This option should be
   placed early on the command line, as it might not affect messages
   related to options that appear before it.
</pre>
 
## Terms of use ##

Starting with version 1.4.x, Deark is distributed under an MIT-style license.
See the "COPYING" file for the license text.

The main Deark license does not necessarily apply to the code in the "foreign"
subdirectory. Each file there may have its own licensing terms.

By necessity, Deark contains knowledge about how to decode various file
formats. This knowledge includes data structures, algorithms, tables, color
palettes, etc. The author(s) of Deark make no intellectual property claims to
this essential knowledge, but they cannot guarantee that no one else will
attempt to do so.

Deark contains at least one bitmapped font, which has been reported to be in
the public domain.

Prior to version 1.4.x, Deark was released as public domain software. This
means that much of this code may be in the public domain, assuming that is
legally permissible in your jurisdiction.

Be particularly wary of relying on Deark to decode archive and compression
formats (tar, ar, gzip, cpio, ...). For example, to decode tar format, you
really should use a battle-hardened application like GNU Tar, not Deark.
Deark's support for such formats is often incomplete, and it usually does no integrity checking.

## How to build ##

See the technical.md file.

## Acknowledgements ##

Thanks to Rich Geldreich for the miniz library.

Thanks to Mike Frysinger, and the authors of compress/ncompress, for liblzw.

Thanks to countless others who have documented the supported file formats.

## Authors ##

Written by Jason Summers, 2014-2017.<br>
Copyright &copy; 2016-2017 Jason Summers<br>
[http://entropymine.com/deark/](http://entropymine.com/deark/)<br>
[https://github.com/jsummers/deark](https://github.com/jsummers/deark)

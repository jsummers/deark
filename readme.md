# Deark #

Deark is a command-line utility that can decode certain types of files, and
either:

1. convert them to a more-modern or more-readable format; or
2. extract embedded files from them

The files it writes are usually named "output.*".

This program is still being developed, and its features are subject to change
without notice.

For additional information, see the [technical.md](technical.md) file.

## Usage ##

    deark [options] [-file] <input-file> [options]
    deark <-h|-version|-modules>

Command-line options:
<pre>
-m &lt;module>
   The "module" to use to process the input file. The default is to autodetect.
   A module may represent one file format, or a group of related formats, or
   may have some special purpose.
   See formats.txt for a list of modules. You usually don't need to use -m,
   unless the format can't be detected, or you want to use a special-purpose
   module such as "copy". See also the -onlydetect option.
-l
   Don't extract, but list the files that would be extracted.
   This option is not necessarily very efficient. Deark will still go through
   all the motions of extracting the files, but will not actually write them.
-main
   Extract only "primary" files (e.g. not thumbnail images).
-aux
   Extract only "auxiliary" files, such as thumbnail images.
-a, -extractall
   Extract more data than usual, including things that are rarely of interest,
   such as comments. See also the "-opt extract..." options.
   Note that, as a general rule, Deark doesn't extract the same data twice.
   In rare cases, the -a option can actually *prevent* it from extracting
   certain data, because it may now, for example, extract a block of Exif
   data, instead of drilling down and extracting the thumbnail image within
   it.
-o &lt;name>
   Output filenames begin with this string. This can include a directory
   path. Default is "output", except in some cases when using -zip/-tar.
-k, -k2, -k3
   "Keep" the input filename, and use it as the initial part of the output
   filename(s). Incompatible with -o.
   -k: Use only the base filename.
   -k2: Use the full path, but not as an actual path.
   -k3: Use the full path, as-is.
-od &lt;directory>
   The directory in which to write output files. The directory must exist.
   This affects only files that Deark writes directly, not e.g. the names of
   ZIP member files when using -zip.
-n
   Do not overwrite existing output files.
-file &lt;input-file>
   This is an alternate syntax for specifying the primary input file. It works
   even if the filename begins with "-".
-file2 &lt;file>
   Some formats are composed of more than one file. In some cases, you can
   use the -file2 option to specify the secondary file. Refer to the
   formats.txt file for details.
-zip
   Write output files to a .zip file, instead of to individual files.
   If the input format is an "archive" format (e.g. "ar" or "zoo"), then
   by default, the filenames in the ZIP archive might not include the usual
   "output.NNN" prefix.
-tar
   Write output files to a .tar file, instead of to individual files.
   Similar to -zip, but may work better with large files.
   The -tostdout option is not currently supported when using -tar.
-arcfn &lt;filename>
   When using -zip/-tar, use this name for the output file. Default is
   "output.zip" or "output.tar".
-ka, -ka2, -ka3
   When uzing -zip/-tar, "keep" the input filename, and use it as the initial
   part of the archive output filename. A suitable filename extenson like
   ".zip" will be appended. Incompatible with -arcfn.
   -ka: Use only the base filename.
   -ka2: Use the full path, but not as an actual path.
   -ka3: Use the full path, as-is.
-extrlist &lt;filename>
   Also create a text file containing a list of the names of the extracted
   files. Format is UTF-8, no BOM, LF terminators. To append to the file
   instead of overwriting, use with "-opt extrlist:append".
-tostdout
   Write the output file(s) to the standard output stream (stdout).
   It is recommended to put -tostdout early on the command line. The
   -msgstostderr option is enabled automatically.
   If used with -zip: Write the ZIP file to standard output.
   Otherwise: The "-maxfiles 1" option is enabled automatically. Including the
   -main option is recommended.
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
-get &lt;n>
   Extract only the file identifed by &lt;n>. The first file is 0.
   Equivalent to "-firstfile &lt;n> -maxfiles 1".
   To unconditionally show the file identifiers, use "-l -opt list:fileid".
-maxfilesize &lt;n>
   Do not write a file larger than &lt;n> bytes. The default is 10 GiB.
   This is an "emergency brake". If the limit is exceeded, Deark will stop all
   processing.
   This setting is for physical output files, so if you use -zip/-tar, it
   applies to the ZIP/tar file, not to the individual member files.
   This option implicitly increases the -maxtotalsize setting to be at least
   &lt;n>.
-maxtotalsize &lt;n>
   Do not write files totaling more than about &lt;n> bytes. The default is
   15 GiB.
   Currently, this feature is not implemented very precisely. The limit is only
   checked when an output file is completed.
-maxdim &lt;n>
   Allow image dimensions up to &lt;n> pixels.
   By default, Deark refuses to generate images with a dimension larger than
   10000 pixels. You can use -maxdim to decrease or increase the limit.
   Increase the limit at your own risk. Deark does not generate large images
   efficiently. In practice, a large dimension will only work if the other
   dimension is very small.
-nobom
   Do not add a BOM to UTF-8 output files generated or converted by Deark. Note
   that if a BOM already exists in the source data, it will not necessarily be
   removed.
-nodens
   Do not try to record the original aspect ratio and pixel density in output
   image files.
-asciihtml
   When generating an HTML document, use ASCII encoding instead of UTF-8. This
   does not change how a browser will render the file; it just makes it larger
   and very slightly more portable.
-nonames
   Make Deark less likely to try to improve output filenames by using names
   from the contents of the input file. The output filenames will be more
   predictable, but less informative.
-nomodtime
   In some cases, mainly when reading archive formats, a last-modified
   timestamp contained in an input file will be used to set the timestamp of an
   output file written directly to your computer (or with -zip/-tar, of a
   member file inside that file). Use -nomodtime to disable this.
   This does not affect internal timestamps that may be maintained when Deark
   converts an item to some other format (such as PNG or HTML).
-opt &lt;module:option>=&lt;value>
   Module-specific and feature-specific options. See formats.txt.
   Caution: Unrecognized or misspelled options will be silently ignored.
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
    -opt archive:subdirs=0
       When using -zip/-tar, disallow subdirectories (the "/" character) in
       member filenames.
    -opt archive:zipcmprlevel=&lt;n>
       When using -zip, the compression level to use, from 0 (none) to 9 (max).
    -opt pngcmprlevel=&lt;n>
       When generating a PNG file, the compression level to use, from 0 (low)
       to 10 (max).
    -opt archive:timestamp=&lt;n>
    -opt archive:repro
       Make the -zip/-tar output reproducible, by not including modification
       times that are not contained in the source file. (That is, don't use the
       current time, or the source file's timestamp.) If you use "repro", the
       times will be set to some arbitrary value. If you use "timestamp", the
       times will be set to the value you supply, in Unix time format (the
       number of seconds since the beginning of 1970).
    -opt keepdirentries=&lt;0|1>
       Select whether an archive file's directory entries are ignored (0), or
       "extracted" (1). For details, see the technical.md file.
    -opt list:fileid=&lt;0|1>
       Select whether the -l (list) option also prints the numeric file
       identifiers.
    -opt extrlist:append
       Affects the -extrlist option.
    -opt extractexif[=0]
    -opt extract8bim
    -opt extractiptc[=0]
    -opt extractplist
       Extract the specified type of data to a file, instead of decoding it.
       For more about the ".8bimtiff" and ".iptctiff" formats, see the
       technical.md file.
    -opt atari:palbits=&lt;9|12|15>
       For some Atari image formats, the number of significant bits per
       palette color. The default is to autodetect.
    -opt macrsrc=&lt;raw|as|ad>
       The preferred way to extract Macintosh resource forks, and data files
       associated with a non-empty resource fork.
        raw = Write the raw resource fork to a separate .rsrc file.
        ad = Put the resource fork in an AppleDouble container (default).
        as = Put both forks in an AppleSingle container.
        mbin = Put both forks in a MacBinary container.
       For input files already in AppleDouble or AppleSingle format, see the
       formats.txt file for more information.
-id
   Stop after the format identification phase. This can be used to show what
   module Deark will run, without actually running it.
-h, -?, -help:
   Print the help message.
   Use with -m to get help for a specific module. Use with a filename to get
   help for the detected format of that file. Note that most modules have no
   module-specific help to speak of.
-version
   Print the version number, and other version information.
-modules
   Print the names of the available modules.
   With -a, list all modules, including internal modules, and modules that
   don't work.
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
-colormode &lt;none|auto|ansi|ansi24|winconsole>
   Control whether Deark uses color and similar features in its debug output.
   Currently, this is mainly used to highlight unprintable characters, and
   preview color palettes (usually requires -d2).
   none: No color (default).
   ansi: Use ANSI codes, but not the less-standard ones for 24-bit color.
   ansi24: Use ANSI codes, including codes for 24-bit color. Works on most
     Linux terminals, and on sufficiently new versions of Windows 10.
   winconsole: Use Windows console commands. Works on all versions of Windows,
     but does not support 24-bit color.
   auto: Request color. Let Deark decide how to do it.
-color
   Same as "-colormode auto".
-enc &lt;ascii|oem>
   Set the encoding of the messages that are printed to the console. This does
   not affect the extracted data files.
   The default is to use Unicode (UTF-8, when the encoding is relevant).
   ascii: Use ASCII characters only.
   oem: [Windows only; has no effect on other platforms] Use the "OEM"
     character set. This may be useful when paging the output with "|more".
-nochcp
   [Windows only] Never change the console OEM code page (to UTF-8).
   For technical reasons, Deark sometimes changes the code page of the Windows
   console it is running in, when its output is going to a pipe or file.
-inenc &lt;ascii|utf8|latin1|latin2|cp437|windows1250|windows1251|windows1252|
     windows1253|windows1254|macroman|palm|riscos|atarist>
   Supply a hint as to the encoding of the text contained in the input file.
   This option is not supported by all formats, and may be ignored if the
   encoding can be reliably determined by other means. Admittedly, it would be
   nice if Deark knew more encodings than this.
-intz &lt;offset>
   Supply a hint as to the time zone used by timestamps contained in the input
   file.
   Many file formats unfortunately contain timestamps in "local time", with no
   information about their time zone. In such cases, the supplied -intz offset
   will be used to convert the timestamp to UTC.
   The "offset" parameter is in hours east of UTC. For example, New York City
   is -5.0, or -4.0 when Daylight Saving Time is in effect.
   This option does not respect Daylight Saving Time. It cannot deal with the
   case where some of the timestamps in a file are in DST, and others are not.
-msgstostderr
   Print all messages to stderr, instead of stdout. This option should be
   placed early on the command line, as it might not affect messages
   related to options that appear before it.
-nodetect &lt;module1,module2,...>
-onlydetect &lt;module1,module2,...>
   Disable autodetection of the formats in the list (or for -onlydetect, the
   formats *not* in the list).
-disablemods &lt;module1,module2,...>
-onlymods &lt;module1,module2,...>
   Completely disable the main functionality, and the autodetection
   functionality, of the modules in the list (or for -onlymods, the modules
   *not* in the list). This can have unexpected side effects, because modules
   often use other modules internally. These options exist mainly to help
   address potential security-related concerns in some workflows.
-modcodes &lt;codes>
   Run the module in a non-default "mode".
   The existence of this option (though not its details) is documented in the
   interest of transparency, but it is mainly for developers, and to make it
   possible to do things whose usefulness was not anticipated.
</pre>

## Exit status ##

Deark sets the exit status to nonzero only if it wasn't able to do its job,
e.g. due to a read or write failure. A malformed input file usually does not
cause such an error, and the exit status will be zero even if an error message
was printed.

However, all fatal errors result in a nonzero exit status, and in extreme cases
it is possible for the input file to cause a fatal error, due to certain
resource limits being exceeded.

## Terms of use ##

Starting with version 1.4.x, Deark is distributed under an MIT-style license.
See the [COPYING](COPYING) file for the license text.

The main Deark license does not necessarily apply to the code in the "foreign"
subdirectory. Each file there may have its own licensing terms. In particular:

uncompface.h: Copyright (c) James Ashton - Sydney University - June 1990
(See the file foreign/readme-compface.txt for details.)

By necessity, Deark contains knowledge about how to decode various
third-party file formats. This knowledge includes data structures,
algorithms, tables, color palettes, etc. The author(s) of Deark make no
intellectual property claims to this essential knowledge, but they cannot
guarantee that no one else will attempt to do so.

Deark contains VGA and CGA bitmapped fonts, which have no known copyright
claims.

Be particularly wary of relying on Deark to decode archive and compression
formats (tar, ar, gzip, cpio, ...). For example, to decode tar format, you
really should use a battle-hardened application like GNU Tar, not Deark.
Deark's support for such formats is often incomplete, and it does not always
do integrity checking.

## How to build ##

See the [technical.md](technical.md) file.

## Acknowledgements ##

Thanks to Rich Geldreich for the miniz library.

Thanks Martin Schoenert for some of the code used by the ZOO format decoder.

Thanks to James Ashton for much of the code used by the X-Face format decoder.

Thanks to Allan G. Weber for the Huffman decompression code used by the StuffIt
format decoder.

Thanks to Mark Adler for the ZIP "implode" decompression code.

Thanks to countless others who have documented the supported file formats.

## Authors ##

Written by Jason Summers, 2014-2020.<br>
Copyright &copy; 2016-2020 Jason Summers<br>
[https://entropymine.com/deark/](https://entropymine.com/deark/)<br>
[https://github.com/jsummers/deark](https://github.com/jsummers/deark)

# Technical information about Deark #

This document is a supplement to the information in the [readme.md](readme.md)
file.

## Mission statement ##

There's not much rhyme or reason to the formats Deark supports, or to its
features. It exists mainly because I've written too many one-off programs to
decode file formats, and wanted to put everything in one place. Part of the
goal is to support (mainly old) formats that are under-served by other
open-source software. Most of the formats it currently supports are related to
graphics, but it is not limited to graphics formats.

One of Deark's purposes is as a tool to find interesting things that are stored
in files, but usually ignored, such as thumbnail images and comments. The "-d"
option is a core feature, and can often be used to learn a lot about the file
in question, whether or not anything is extracted from it.

Another purpose is digital preservation. It is meant to encapsulate information
about old formats that might otherwise be hard to find.

One guideline is that any image format supported by XnView, and not by any
well-maintained open source software, is a candidate for being supported, no
matter how obscure it may be.

## Security ##

Deark is intended to be safe to use with untrusted input files, but there are
no promises. It is written in C, and vulnerabilities very likely exist.

A strategically-designed input file can definitely cause Deark to use a
disproportionate amount of system resources, such as disk space or CPU time.
Deark does enforce some resource limits, but not consistently. This is a
difficult problem to solve.

## The filename problem ##

When Deark writes a file, it has to decide what to name it. This can be a very
difficult problem. For one thing, what is and is not a valid filename depends
on the user's platform, and the relevant filesystem type. For another thing,
there are security hazards everywhere. Deark should not try to write a file
named "/etc/passwd", for example.

Also, there are a near-limitless number of reasonable ways to construct an
output filename, with an elaborate decision tree to select the best behavior
in various circumstances.

Deark essentially throws up its hands and gives up. By default, it names all
output filenames to start with "output.". It overwrites existing files with no
warning. It bans all ASCII characters that could conceivably be problematical,
as well as any non-ASCII characters that don't appear on its whitelist.

When Deark writes to a ZIP file (the "-zip" option), it doesn't have to worry
about what to name the internal files. It can palm that problem off onto your
unzip program. It is slightly more tolerant in this case, but not as tolerant
as it could be.

Currently, directory paths are never maintained as such. I.e., Deark never
writes a file to anything but the current directory (unless the -o option
contains a "/"). It doesn't even do this when writing to a ZIP file (though
this may change in future version).

## The "Is this one format or two?" problem ##

It's often hard to decide whether a format should get its own module, or be a
part of some other module. Deark has some guidelines for this, but doesn't
always follow them consistently.

Modules are not supposed to make use of the input filename, except during
format detection. So if two formats can't be distinguished in any other way,
they generally have to be placed in separate modules. 

## Format detection ##

If the user does not use the "-m" option, then Deark will try to guess the best
module to use. It prefers to do this using only the contents of the file, but
unfortunately, there are many file formats that cannot realistically be
identified in such a way. So, in some cases, Deark also uses the filename,
especially the filename extension.

It does not use any other file attributes, such as the last-modified time or
the executable-flag; though this could change in future versions.

The filename is only used for format detection, and not for any other purpose.
This helps make its behavior safe and predictable. The options -m, -start, and
-fromstdin are among those that might need special cases added, if that were
not the case.

This behavior *might* be changed in the future (as an option?), because some
formats store important information in the filename, and having a separate
module for each possibility isn't always feasible. For example, with Unix
compress format, there is no other way to construct a good output filename, so
Deark has to settle for a generic name like "output.000.bin".

## Character encoding (console) ##

The "-d" option prints a lot of textual information to the console, some of
which is not ASCII-compatible. Non-ASCII text can sometimes cause problems.

On Windows, Deark generally does the right thing automatically. However, if you
are redirecting the output to a file or a pipe, there are cases where the
"-enc" option can be helpful. 

On Unix-like platforms, UTF-8 output will be written to the terminal,
regardless of your LANG (etc.) environment variable. You can use "-enc ascii"
to print only ASCII. (This is not ideal, but seriously, it's time to switch to
UTF-8 if at all possible.)

On Unix-like platforms, command-line parameters are assumed to be in UTF-8.

## Character encoding (output files) ##

When Deark generates a text file, its preferred encoding is UTF-8, with a BOM
(unless you use "-nobom"). But there are many cases where it can't do that,
because the original encoding is undefined, unsupported, or incompatible with
Unicode. In such cases, it just writes out the original bytes as they are.

If the text was already encoded in UTF-8, Deark does not behave perfectly
consistently. Some modules copy the bytes as they are, while other sanitize
them first.

Deark keeps the end-of-line characters as they are in the original file. If it
has to generate end-of-line characters of its own, it uses Unix-style line-feed
characters.

## Executable output files ##

Most file attributes (such as file ownership) are ignored when extracting
files, but Deark does try to maintain the "executable" status of output
files, for formats which store this attribute. The Windows version of Deark
does not use this information, except when writing to a ZIP file.

This is a simple yes/no flag. It does not distinguish between
owner-executable and world-executable, for example.

## Modification times ##

In certain cases, Deark tries to maintain the modification time of the original
file.

If a timestamp does not include a time zone, the time will be assumed to be in
Universal Time (UTC). This is usually wrong, but since Deark is intended for
use with ancient files of unknown provenance, there is really nothing else it
can do (short of asking the user, which would be annoying, and almost always
useless). The timestamp was presumably intended to be in the original user's
time zone, but there is no reason to think that the *current* user's time zone
would be relevant in any way.

Note that if you are extracting to a system that does not store file times in
UTC (often the case on Windows), the timestamps may not be very accurate.

## Modification times and thumbnails ##

Some thumbnail image formats store the last-modified time of the original file.
This raises the question of whether Deark should use this as the last-modified
time of the extracted thumbnail file. Currently, Deark *does* do this, but it
must be acknowledged that there's something not quite right about it, because
the thumbnail may have been created much later than the original image.

## I've never heard of that format! ##

For the identities of the formats supported by Deark, see

- [File format wiki: Electronic File Formats](http://fileformats.archiveteam.org/wiki/Electronic_File_Formats)
- [File format wiki: Graphics](http://fileformats.archiveteam.org/wiki/Graphics)

## Other information ##

By design, Deark does not look at any files that don't explicitly appear on the
command line. In the future, there might be an option to change this behavior,
and automatically try to find related files.

Bitmap fonts are converted to images. Someday, there might be an option to
convert them to some portable font format, but that is difficult to do well.

## How to build ##

Deark is written in C. On a Unix-like system, typing "make" from a shell prompt
will (hopefully) be sufficient:

    $ make

This will build an executable file named "deark". Deark has no dependencies,
other than the standard C libraries.

It is safe to build Deark using "parallel make", i.e. "make -j". This will
speed up the build, in most cases.

If you want to install it in a convenient location, just copy the "deark" file.
For example:

    $ sudo cp deark /usr/local/bin/

For Microsoft Windows, the project files in proj/vs2008 should work for Visual
Studio 2008 and later. Alternatively, you can use Cygwin.

## Developer notes ##

The Deark source code is structured like a library, but it's not intended to be
used as such. The error handling methods, and error messages, are not really
suitable for use in a library.

A regression test suite does exist for Deark, but is not available publicly at
this time.

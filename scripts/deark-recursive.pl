#!/usr/bin/perl -w
# A Perl5 sample script that uses Deark to try to recursively extract all the
# files from the files given on the command line.
# All extracted files will be written to the current directory, and will have
# names beginning with "output.".
# It is normal for error messages to be printed, when unsupported formats are
# extracted.
# This script is quick and dirty. Use at your own risk.
# Terms of use: Public domain
# By Jason Summers, 2018
use strict;

my $deark_exe = "/usr/local/bin/deark";

sub do_onefile {
  my $nlistref = $_[0];
  my $fn = $_[1];

  my $code = join('.', @$nlistref);
  print "extracting from: $fn\n";

  my @args = ($deark_exe, $fn, "-extrlist", "output.list",
     "-a", "-o", "output.$code");
  system(@args);

  if($#$nlistref > 10) {
    return; # emergency brake
  }

  # Make a list of the filenames that the previous command extracted.
  my @outputfns = ();
  open(my $extrlist, "<", "output.list") or die "Can't read output.list";
  while(<$extrlist>) {
    my $line = $_;
    chomp($line);
    push @outputfns, $line;
  }
  close($extrlist);
  unlink("output.list");

  # Now we have the list. Call ourselves recursively.
  my $counter = 0;
  foreach my $fn (@outputfns) {
    push @$nlistref, sprintf "%03d", $counter;
    do_onefile($nlistref, $fn);
    pop @$nlistref;
    $counter++;
  }
}

sub main {
 my @nlist = (); # A stack used to construct output filenames

 foreach my $fn (@ARGV) {
   my $fn_sanitized = $fn;
   if($fn_sanitized =~ /^(.*)[\/\\](.*)$/) { # Only use basename
      if($2 ne "") {
         $fn_sanitized = $2;
      }
   }
   $fn_sanitized =~ s/[\/\\:\*\?\"<>\|\c@-\c_]/_/g;
   push @nlist, $fn_sanitized;
   do_onefile(\@nlist, $fn);
   pop @nlist;
 }
}

main();

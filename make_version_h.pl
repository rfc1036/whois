#!/usr/bin/perl

use warnings;
use strict;
use autodie;

my $changelog = $ARGV[0] or die "Usage: $0 debian/changelog\n";

open(my $fh, '<', $changelog);
my $line = <$fh>;
close($fh);

my ($ver) = $line =~ /^whois \s+ \( ( [^\)]+ ) \) \s+ \S+/x;
die "Version number not found in $changelog!\n" if not $ver;

$ver =~ s/ ( ~bpo\d+\+\d+ | \+b\d+ | ~deb\d+.* | ubuntu\d+ | \+dyson\d+ ) $//x;

# The version number must not deviate from this format or the -V option
# to RIPE-like servers will break. If needed, update the previous regexp.
# This may not be true anymore in 2019.
die "Invalid version number in $changelog!\n"
	unless $ver =~ /^ \d+\.\d+ ( \.\d+ )? $/x;

# This is the version number used in the help messages.
print qq|#define VERSION "$ver"\n|;

# This is the string sent to RIPE-like servers as the argument of -V.
print qq|#define IDSTRING "Md$ver"\n|;


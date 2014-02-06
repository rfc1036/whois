#!/usr/bin/perl

use warnings;
use strict;

my $changelog = $ARGV[0] or die "Usage: $0 debian/changelog\n";

open(my $fh, '<', $changelog) or die "open($changelog): $!";
my $line = <$fh>;
close($fh) or die "close($changelog): $!";

my ($ver) = $line =~ /^whois \s+ \( ( [^\)]+ ) \) \s+ \S+/x;
die "Version number not found in $changelog!\n" if not $ver;

$ver =~ s/ ( ~deb\d+.* | ubuntu\d+ ) $//x;

# The version number must not deviate from this format or the -V option
# to RIPE-like servers will break. If needed, update the previous regexp.
die "Invalid version number in $changelog!\n"
	unless $ver =~ /^ \d+\.\d+ ( \.\d+ )? $/x;

print qq|#define VERSION "$ver"\n|;


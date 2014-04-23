#!/usr/bin/perl

use warnings;
use strict;

while (<>) {
	chomp;
	s/#.*$//;
	s/^\s+//; s/\s+$//;
	next if /^$/;

	die "format error: $_" if not (/^([\d\.]+)\s+([\d\.]+)\s+([\w\.]+)$/);
	my $f = $1; my $l = $2; my $s = $3;

	print qq|{ ${f}, ${l}, "|;
	if ($s =~ /\./) {
		print "$s";
	} else {
		print "whois.$s.net";
	}
	print qq|" },\n|;
}


#!/usr/bin/perl
# SPDX-License-Identifier: GPL-2.0-or-later

use warnings;
use strict;

my $last_l = 0;

while (<>) {
	chomp;
	s/#.*$//;
	s/^\s+//; s/\s+$//;
	next if /^$/;

	die "format error: $_" if not (/^([\d\.]+)\s+([\d\.]+)\s+([\w\.]+)$/);
	my $f = $1; my $l = $2; my $s = $3;

	die "constraint violated: $l < $last_l" if $l < $last_l;
	$last_l = $l;

	print "{ ${f}, ${l}, \"";
	if ($s =~ /\./) {
		print "$s";
	} else {
		print "whois.$s.net";
	}
	print qq(" },\n);
}


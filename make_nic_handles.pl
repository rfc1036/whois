#!/usr/bin/perl

use warnings;
use strict;

while (<>) {
	chomp;
	s/#.*$//;
	s/^\s+//; s/\s+$//;
	next if /^$/;

	die "format error: $_" if not
		(my ($a, $b) = /^(-\w+)\s+([\w\d\.:-]+)$/);

	print qq|    "$a",\t"$b",\n|;
}


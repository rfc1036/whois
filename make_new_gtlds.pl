#!/usr/bin/perl

use warnings;
use strict;

while (<>) {
	chomp;
	s/#.*$//;
	s/^\s+//; s/\s+$//;
	next if /^$/;

	die "format error: $_" if not /^((?:xn--)?[a-z0-9]+)$/;

	print qq|    "$_",\n|;
}


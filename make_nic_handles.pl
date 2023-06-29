#!/usr/bin/perl
# SPDX-License-Identifier: GPL-2.0-or-later

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


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
		(my ($a, $b, $c) = /^([a-z0-9.-]+)\s+([a-z0-9-]+)(?:\s+(.+))?$/);

	if ($c) {
		print qq|    { "$a",\t"$b",\t"$c" },\n|;
	} else {
		print qq|    { "$a",\t"$b",\tNULL },\n|;
	}
}


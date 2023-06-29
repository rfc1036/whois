#!/usr/bin/perl
# SPDX-License-Identifier: GPL-2.0-or-later

use warnings;
use strict;

while (<>) {
	chomp;
	s/#.*$//;
	s/^\s+//; s/\s+$//;
	next if /^$/;

	die "format error: $_" if not /^(xn--[a-z0-9-]+|[a-z]+)$/;

	print qq|    "$_",\n|;
}


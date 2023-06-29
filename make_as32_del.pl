#!/usr/bin/perl
# SPDX-License-Identifier: GPL-2.0-or-later

use warnings;
use strict;

while (<>) {
	chomp;
	s/#.*$//;
	s/^\s+//; s/\s+$//;
	next if /^$/;

	my ($fh, $fl, $lh, $ll, $s, $f, $l);
	if (($fh, $fl, $lh, $ll, $s) =
			/^(\d+)\.(\d+)\s+(\d+)\.(\d+)\s+([\w\.-]+)$/) {
		$f = ($fh << 16) + $fl;
		$l = ($lh << 16) + $ll;

		my $server = ($s =~ /\./) ? $s : "whois.$s.net";
		print qq|{ ${f}u, ${l}u,\t"$server" },\t/* $fh.$fl $lh.$ll */\n|;
	} elsif (($f, $l, $s) = /^(\d+)\s+(\d+)\s+([\w\.-]+)$/) {
		my $server = ($s =~ /\./) ? $s : "whois.$s.net";
		print qq|{ ${f}u, ${l}u,\t"$server" },\n|;
	} else {
		die "format error: $_";
	}
}


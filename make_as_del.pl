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

	my ($fh, $fl, $lh, $ll, $s, $f, $l);
	my $comment = '';
	if (($fh, $fl, $lh, $ll, $s) =
			/^(\d+)\.(\d+)\s+(\d+)\.(\d+)\s+([\w\.-]+)$/) {
		$f = ($fh << 16) + $fl;
		$l = ($lh << 16) + $ll;
		$comment = qq|\t/* $fh.$fl $lh.$ll */|;
	} elsif (($f, $l, $s) = /^(\d+)\s+(\d+)\s+([\w\.-]+)$/) {
	} else {
		die "format error: $_";
	}

	die "constraint violated: $l < $last_l" if $l < $last_l;
	$last_l = $l;

	my $server = ($s =~ /\./) ? $s : "whois.$s.net";
	print qq|{ ${f}u, ${l}u,\t"$server" },$comment\n|;
}


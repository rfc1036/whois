#!/usr/bin/perl

use warnings;
use strict;

while (<STDIN>) {
	chomp;
	s/^\s*(.+)\s*$/$1/;
	s/\s*#.*$//;
	next if /^$/;

	my ($fh, $fl, $lh, $ll, $s) = /^(\d+)\.(\d+)\s+(\d+)\.(\d+)\s+([\w\.-]+)$/;
	die "format error: $_" unless $s;

	my $f = ($fh << 16) + $fl;
	my $l = ($lh << 16) + $ll;
	my $server = ($s =~ /\./) ? $s : "whois.$s.net";

	print qq({ $f, $l,\t"$server" },\t/* $fh.$fl $lh.$ll */\n);
}


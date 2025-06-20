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
		(my ($a, $b) = /^\.(\w[\w\d\.-]+)\s+([\w\d\.:-]+|[A-Z]+\s+.*)$/);

	$b =~ s/^W(?:EB)?\s+/\\x01/;
	$b =~ s/^VERISIGN\s+/\\x04" "/;
	$b = "\\x03" if $b eq 'NONE';
	$b =~ s/^RECURSIVE\s+/\\x08" "/;
	$b = "\\x08$b" if $b eq 'whois.flexireg.net';
	$b = "\\x08$b" if $b eq 'whois.nixiregistry.in';
	$b = "\\x0C" if $b eq 'ARPA';
	$b = "\\x0D" if $b eq 'IP6';
	print qq|    "$a",\t"$b",\n|;
}


#!/usr/bin/perl -w

use strict;

while (<>) {
	chomp;
	s/^\s*(.*)\s*$/$1/;
	s/\s*#.*$//;
	next if /^$/;
	die "format error: $_" unless
		(my ($a, $b) = /^([\w\d\.-]+)\s+([\w\d\.:-]+|[A-Z]+\s+.*)$/);
	$b =~ s/^W(?:EB)?\s+/\\001/;
	$b =~ s/^M(?:SG)?\s+/\\002/;
	$b = "\\003" if ($b eq 'NONE');
	print "    \"$a\",\t\"$b\",\n";
}


#!/usr/bin/perl -w

use strict;

while (<>) {
	chomp;
	s/^\s*(.*)\s*$/$1/;
	s/\s*#.*$//;
	next if /^$/;
	die "format error: $_" unless (/^([\w\d\.-]+)\s+([\w\d\.:-]+)$/);
	print "    \"$1\",\t\"$2\",\n";
}


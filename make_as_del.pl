#!/usr/bin/perl -w

use strict;

while (<>) {
	chomp;
	s/^\s*(.*)\s*$/$1/;
	s/\s*#.*$//;
	next if /^$/;
	die "format error: $_" unless (/^([\d\.]+)\s+([\d\.]+)\s+([\w\.]+)$/);
	my $f=$1; my $l=$2; my $s=$3;
	print "{ ${f}, ${l}, \"";
	if ($s =~ /\./) {
		print "$s";
	} else {
		print "whois.$s.net";
	}
	print "\" },\n";
}


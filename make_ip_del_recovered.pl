#!/usr/bin/perl
# https://www.iana.org/assignments/ipv4-recovered-address-space/ipv4-recovered-address-space-2.csv

use warnings;
use strict;
use autodie;

use Text::CSV;

my $csv = Text::CSV->new;

open(my $in, '<', 'ipv4-recovered-address-space-2.csv');
open(my $out, '>', 'ip_del_recovered.h');

while (my $row = $csv->getline($in)) {
	next if $row->[0] eq 'Start address';
	next if $row->[5] ne 'ALLOCATED';

	my ($b1, $b2, $b3, $b4) = split(/\./, $row->[0]);
	my ($e1, $e2, $e3, $e4) = split(/\./, $row->[1]);
	die if not defined $b4 or not defined $e4;

	print $out '{ ' .
		(($b1 << 24) + ($b2 << 16) + ($b3 << 8) + $b4) . 'UL, ' .
		(($e1 << 24) + ($e2 << 16) + ($e3 << 8) + $e4) . 'UL, ' .
		'"' . $row->[4] . qq|" },\n|;
}

close($in);
close($out);


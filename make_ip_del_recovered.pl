#!/usr/bin/perl
# https://www.iana.org/assignments/ipv4-recovered-address-space/ipv4-recovered-address-space-2.csv

use warnings;
use strict;
use autodie;

use Text::CSV;
use Net::CIDR;
use Net::IP;

my $csv = Text::CSV->new;

open(my $in, '<', 'ipv4-recovered-address-space-2.csv');
open(my $out, '>', 'ip_del_recovered.h');

while (my $row = $csv->getline($in)) {
	next if $row->[0] eq 'Start address';
	next if $row->[5] ne 'ALLOCATED';

	print $out '/* ' . $row->[0] . ' - ' . $row->[1] . " */\n";
	my @networks =
		map { Net::IP->new($_) }
		Net::CIDR::range2cidr($row->[0] . '-' . $row->[1]);
	print $out sprintf(qq|{ %sUL, %sUL, "%s" },\n|,
		$_->intip,
		((~(0xffffffff >> $_->prefixlen)) & 0xffffffff),
		$row->[4]
	) foreach @networks;
}

close($in);
close($out);


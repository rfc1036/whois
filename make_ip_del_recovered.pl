#!/usr/bin/perl
# https://www.iana.org/assignments/ipv4-recovered-address-space/ipv4-recovered-address-space-2.csv

use warnings;
use strict;
use autodie;

use Text::CSV;
use Net::Patricia;
use Net::CIDR;
use Net::IP;

my $csv = Text::CSV->new;
my $pt = parse_ip_del('ip_del_list');

open(my $in, '<', 'ipv4-recovered-address-space-2.csv');
open(my $out, '>', 'ip_del_recovered.h');

while (my $row = $csv->getline($in)) {
	next if $row->[0] eq 'Start address';
	next if $row->[5] ne 'ALLOCATED';
	my ($first_ip, $last_ip, undef, undef, $server) = @$row;

	my @networks =
		grep {
			my $server_recovered = $pt->match_string($_->ip);
			$server_recovered and $server_recovered ne $server;
		}
		map { Net::IP->new($_) }
		Net::CIDR::range2cidr($first_ip . '-' . $last_ip);
	next if not @networks;

	print $out "/* $first_ip - $last_ip */\n";
	print $out sprintf(qq|{ %sUL, %sUL, "%s" },\n|,
		$_->intip,
		((~(0xffffffff >> $_->prefixlen)) & 0xffffffff),
		$server
	) foreach @networks;
}

close($in);
close($out);
exit;

sub parse_ip_del {
	my ($file) = @_;

	my $pt = new Net::Patricia;

	open(my $in, '<', $file);
	while (<$in>) {
		# this code is copied from make_ip_del.pl
		chomp;
		s/#.*$//;
		s/^\s+//; s/\s+$//;
		next if /^$/;

		die "format error: $_" if not /^([\d\.]+)\/(\d+)\s+([\w\.]+)$/;
		my $network = "$1/$2";
		my $server = $3;

		$server = "whois.$server.net" if $server !~ /\./;

		$pt->add_string($network, $server) or die;
	}

	return $pt;
}


#!/usr/bin/perl -w

use IO::Socket;
use strict;

my %check=(
	'whois.io'	=> 'whois.io',
	'whois.nic.cx'	=> 'nic.cx',
	'whois.nic.gi'	=> 'nic.gi',
	'whois.nic.ly'	=> 'nic.ly',
	'whois.nic.pw'	=> 'nic.pw',
	'whois.nic.so'	=> 'nic.so',
	'whois.nic.st'	=> 'nic.st',
	'whois.uprr.pr'	=> 'uprr.pr',
	'whois.nplus.gf'	=> 'nplus.gf',
	'rwhois.reacciun.ve'	=> 'reacciun.ve',
	'whois.adamsnames.tc'	=> 'adamsnames.vg',
	'whois.idnic.net.id'	=> 'idnic.net.id',
	'whois.ncst.ernet.in'	=> 'ncst.ernet.in',
);

my @ripetest=('-V wC2.0', '-V2.0Md', '-VMd4.4');
my %ripeserv=qw(
	whois.ripe.net	dfn.de
	whois.aunic.net	connect.com.au
	whois.connect.com.au connect.com.au
	whois.ra.net	AS1
	whois.apnic.net	24.192.0.0
	whois.nic.it	nic.it
	whois.ans.net	AS1
	whois.ripn.net	demos.su
	whois.nic.fr	nic.fr
	whois.nic.net.sg	nic.net.sg
	whois.metu.edu.tr metu.edu.tr
);

open(LIST, 'tld_serv_list');
while (<LIST>) {
	chomp;
	next if /^#/;
	my ($tld, $serv, $junk)=split;
	next unless ($tld =~/\.[a-z]{2}$/);	# skip non-cctld
	# I'm sure these won't move without notifying...
	next if ($serv =~ /(?:isi\.edu|internic.net)/);

	if ($serv eq 'whois.ripe.net') {
		$tld =~ s/^\.//;
		print ">>>>>>>>>Querying $serv ($tld) for $tld<<<<<<<<<<\n";
		print whois("-i domain $tld", $serv);	# untested
		print "\n";
		next;
	}
	my $q;
	if ($serv =~ /$tld$/) {
		$q = $serv; $q =~ s/.*\.([-a-z0-9]+?\...)$/$1/;	# we know a real domain
	} else {
		$q = "nic$tld";		# make a random domain and try anyway
	}
	$tld =~ s/^\.//;
	print ">>>>>>>>>Querying $serv ($tld) for $q<<<<<<<<<<\n";
	print whois($q, $serv);
	print "\n";
}
close LIST;

print "#" x 78 . "\n";
foreach (keys %check) {
	print ">>>>>>>>>Querying $_ for $check{$_}<<<<<<<<<<\n";
	print whois($check{$_}, $_);
	print "\n";
}
exit 0;

print "#" x 78 . "\n";
foreach my $s (keys %ripeserv) {
	foreach (@ripetest) {
		my $q = "$_ $ripeserv{$s}";
		print ">>>>>>>>>Querying $s for $q<<<<<<<<<<\n";
		print whois($q, $s);
		print "\n";
	}
}
exit 0;

sub whois {
	my ($query, $serv, $port) = @_;
	my (@result, $remote);

	eval {
		local $^W=0;
		$remote = IO::Socket::INET->new(
			Timeout => 15, PeerAddr => $serv, PeerPort => $port || 43
		);
	};
	if (defined $remote and ($@ eq '')) {
		print $remote "$query\r\n";
		@result = <$remote>;
		close $remote;
	} elsif ($@ ne '') {
		@result = ("FATAL: $@");
	} else {
# FIXME should disconnect from rwhois servers or the connection will hang
# until the timeout of the server
		@result = ("$!\n");
	}
	return @result;
}


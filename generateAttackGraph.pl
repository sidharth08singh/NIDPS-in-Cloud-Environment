#!/usr/bin/perl

my $alertfile = '/var/log/snort/alert';
my $sagfile = '/var/log/snort/attackgraph';

open(my $fh, '<:encoding(UTF-8)', $alertfile)
	or die "Could not open file '$alertfile' $!";

#03/19-17:37:02.465116  [**] [1:10000:0] ***Alert! DOS LAND ATTACK : POSSIBLE SYN FLOOD FROM SPOOFED IP ADDRESSES*** [**] [Priority: 0] {TCP} 89.220.63.182:14352 -> 30.0.0.1:8000

my %mac;
my %attackCode;


my $timestamp;
my $attackType;
my $proto;
my $srcip, $srcmac, $srcport;
my $dstip, $dstmac, $dstport;

$mac{'10.0.0.3'} = '01:01:01:01:01:01';
$mac{'30.0.0.1'} = '01:01:01:01:01:02';
$mac{'syn_attack'} = '01:01:01:01:01:03';
$mac{'icmp_attack'} = '01:01:01:01:01:04';

$attackCode{'syn'} = 0;
$attackCode{'icmp'} = 1;
$attackCode{'scan'} = 2;


my $reSYN = '(\d\d\/\d\d.\d\d.\d\d.\d\d.\d+)\s+.*?\*\*\*(.*)?\*\*\*.*?{(\w+)}\s+(\d+.\d+.\d+.\d+):(\d+)\s+\W\W\s+(\d+.\d+.\d+.\d+):(\d+)';

while(my $row = <$fh>) {
	chomp $row;
	print "Row : $row\n\n";
	if($row =~ /$reSYN/) {
		print "$1 :: $2 :: $3 :: $4 :: $5 :: $6 :: $7\n\n";
		$timestamp = $1;
		$attackType = $attackCode{'syn'};
		$proto = $3;
		$srcip = $4;
		$srcport = $5;
		$srcmac = $mac{'syn_attack'};
		$dstip = $6;
		$dstport = $7;
		$dstmac = $mac{$dstip};
		print "$timestamp :: $attackType :: $proto :: $srcip :: $srcport :: $srcmac :: $dstip :: $dstport :: $dstmac\n\n";
		open (my $fh2, '>>', $sagfile);
		print $fh2 "$timestamp::$attackType::$proto::$srcip::$srcport::$srcmac::$dstip::$dstport::$dstmac\n";
		close($fh2);
	}
}

close($fh);

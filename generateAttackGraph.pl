#!/usr/bin/perl

##################################################################################
########## Script to generate an attack graph from Snort alert file ##############
##################################################################################

my $status;
print "************************************************************\n";
print "***** Starting SNORT in Daemon Mode : STATUS : $status *****\n";
print "************************************************************\n";
$status = system("snort -D -de -c /etc/snort/snort.conf -A fast");
if($status < 0) {
	exit(1);
}

my $alertfile = '/var/log/snort/alert';
my $sagfile   = '/var/log/snort/attackgraph';

while(1) {
	open(my $fh, '<:encoding(UTF-8)', $alertfile)
		or die "Could not open file '$alertfile' $!";

	my %mac;
	my %attackCode;

	my $timestamp;
	my $attackType;
	my $proto;
	my $srcip, $srcmac, $srcport;
	my $dstip, $dstmac, $dstport;

	$mac{'10.0.0.5'}      = '00:00:00:00:00:05';
	$mac{'10.0.0.6'}      = '00:00:00:00:00:06';
	$mac{'syn_attack'}    = '00:00:00:00:00:01';
	$mac{'icmp_attack'}   = '00:00:00:00:00:02';
	$mac{'nmap_scan'}     = '00:00:00:00:00:03';
	$mac{'legit_traffic'} = '00:00:00:00:00:04';

	$attackCode{'syn'}  =  0;
	$attackCode{'icmp'} = 1;
	$attackCode{'scan'} = 2;

	my $reICMP = '(\d\d\/\d\d.\d\d.\d\d.\d\d.\d+)\s+.*?\*\*\*(.*)?\*\*\*.*?{(\w+)}\s+(\d+.\d+.\d+.\d+)\s+\W\W\s+(\d+.\d+.\d+.\d+)';
	my $reSYN  = '(\d\d\/\d\d.\d\d.\d\d.\d\d.\d+)\s+.*?\*\*\*(.*)?\*\*\*.*?{(\w+)}\s+(\d+.\d+.\d+.\d+):(\d+)\s+\W\W\s+(\d+.\d+.\d+.\d+):(\d+)';
	my $reNMAP = '(\d\d\/\d\d.\d\d.\d\d.\d\d.\d+)\s+.*?(SCAN.*?)Priority:\s+\d.\s+{(\w+)}\s+(\d+.\d+.\d+.\d+):(\d+)\s+\W\W\s+(\d+.\d+.\d+.\d+):(\d+)';

	my $syn_attack_detected = 0;
	my $icmp_attack_detected = 0;
	my $nmap_scan_detected = 0;


	open (my $fh2, '>>', $sagfile);

	while(my $row = <$fh>) {
		chomp $row;
		#print "Row : $row\n\n";
		if($row =~ /$reSYN/) {
			if($syn_attack_detected == 0) {
				#print "$1 :: $2 :: $3 :: $4 :: $5 :: $6 :: $7\n\n";
				$timestamp = $1;
				$attackType = $attackCode{'syn'};
				$proto = $3;
				$srcip = $4;
				$srcport = $5;
				$srcmac = $mac{'syn_attack'};
				$dstip = $6;
				$dstport = $7;
				$dstmac = $mac{$dstip};
				#print "$timestamp :: $attackType :: $proto :: $srcip :: $srcport :: $srcmac :: $dstip :: $dstport :: $dstmac\n\n";
				print $fh2 "$timestamp,$attackType,$proto,$srcip,$srcport,$srcmac,$dstip,$dstport,$dstmac\n";
				$syn_attack_detected = 1;
			}
		}

		elsif($row =~ /$reICMP/) {
			if($icmp_attack_detected == 0) {
				#print "$1 :: $2 :: $3 :: $4 :: $5\n\n";
				$timestamp = $1;
				$attackType = $attackCode{'icmp'};
				$proto = $3;
				$srcip = $4;
				$srcmac = $mac{'icmp_attack'};
				$dstip = $5;
				$dstmac = $mac{$dstip};
				#print "ICMP Attack $timestamp :: $attackType :: $proto :: $srcip :: $srcmac :: $dstip :: $dstmac\n\n";
				print $fh2 "$timestamp,$attackType,$proto,$srcip,$srcmac,$dstip,$dstmac\n";
				$icmp_attack_detected = 1;
			}
		}

		elsif($row =~ /$reNMAP/) {
			if($nmap_scan_detected == 0) {
				#print "$1 :: $2 :: $3 :: $4 :: $5 :: $6 :: $7\n\n";
				$timestamp = $1;
				$attackType = $attackCode{'scan'};
				$proto = $3;
				$srcip = $4;
				$srcport = $5;
				$srcmac = $mac{'nmap_scan'};
				$dstip = $6;
				$dstport = $7;
				$dstmac = $mac{$dstip};
				#print "$timestamp :: $attackType :: $proto :: $srcip :: $srcport :: $srcmac :: $dstip :: $dstport :: $dstmac\n\n";
				print $fh2 "$timestamp,$attackType,$proto,$srcip,$srcport,$srcmac,$dstip,$dstport,$dstmac\n";
				$nmap_scan_detected = 1;
			}	
		}
	}

	close($fh2);
	close($fh);
	
	$status = system("echo \" \" > /var/log/snort/alert");
	print "\n*** Cleared SNORT ALERT File : STATUS : $status\n";
	$output = `ps -aux | grep \"snort -D -de\"`;
	print "\n*** Snort Process ID : $output\n";
	if ($output =~ /root\s+(\d+)\s+/) {
		print "\nSnort Process : $1\n";
		$status = system("kill -9 $1");
		print "\n*** Killed Snort : STATUS : $status\n";
	}

	sleep(5);

	$status = system("snort -D -de -c /etc/snort/snort.conf -A fast");
	print "**************************************************************\n";
	print "***** Restarting SNORT in Daemon Mode : STATUS : $status *****\n";
	print "**************************************************************\n";
	if($status < 0) {
		exit(1);
	}

	sleep(20);
}

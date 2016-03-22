#!/usr/bin/perl

while(1) {
	`iperf -t 2 -c 10.0.0.5`;
        sleep(10);
}

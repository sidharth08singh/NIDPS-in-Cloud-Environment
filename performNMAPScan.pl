#!/usr/bin/perl

while(1) {
	sleep(20);
	system("nmap -sX 10.0.0.5");
	sleep(20);
}

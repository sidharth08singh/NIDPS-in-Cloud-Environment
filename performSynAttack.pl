#!/usr/bin/perl

while(1) {
	system("sudo hping3 -i u1 -S -p 8000 -c 1000 10.0.0.5");
	sleep(5);
}

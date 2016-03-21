#!/usr/bin/perl
print "********************************************************************\n";
print "Starting setup on Switch\n";
print "********************************************************************\n";

system("ovs-vsctl -- set Bridge s1 mirrors=\@m -- --id=\@s1-eth6 get Port s1-eth6 -- --id=\@s1-eth5 get Port s1-eth5 -- --id=\@m create Mirror name=mymirror select-dst-port=\@s1-eth6 output-port=\@s1-eth5");


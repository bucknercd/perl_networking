#!/usr/bin/perl -w
# NOTE: This file MUST be run as ROOT
#Filename: scan.pl
use strict;
use IO::Socket::INET;
#use lib '/home/chris/cpan/lib/';
use Net::Ping;
use Data::Dumper;

my $DEBUG = 0;
my $MAX_PORT = 64000;
my $PUBLIC_IP;
my $LOCAL_IP;

#### MAIN ####
set_local_ip();
set_public_ip();
display_pc_info();
my $target = shift || 'localhost';
if ($target eq '-h' or $target =~ /help/i) {
    print usage();
    exit;
}
my $port_flag = shift || '?';
my $port_scan = 0;
$port_scan = 1 if $port_flag eq '-p';

if (substr($target, -2) eq '.0') {
    print "Scanning network $target/24 ...\n=====================================================\n";
    my $base_target = substr($target, 0, -1);
    for (my $i = 1; $i < 255; $i++) {
        $target = $base_target . $i;
        if (is_alive($target) && $port_scan == 1) {
            port_scan($target);
        }
    }
} else {
    print "Scanning $target ...\n=====================================================\n";
    if (is_alive($target) && $port_scan == 1) {
        port_scan($target);
    }
}

sub display_pc_info {
    my $user = `whoami`;
    my $hostname = `hostname`;
    chomp($user);
    chomp($hostname);
    print "\nSCAN INFORMATION\n=====================================================\n";
    printf("%-15s%-15s\n%-15s%-15s\n%-15s%-15s\n%-15s%-15s\n\n", "USER:",$user, "HOSTNAME:", $hostname, "PRIVATE IP:", $LOCAL_IP, "PUBLIC IP:", $PUBLIC_IP);
}

sub set_public_ip {
    system("wget -q http://ipchicken.com");
    open(FH, "index.html");
    my @lines = <FH>;
    foreach (@lines) { 
	if (/((\d{1,3})(\.)){3}\d{1,3}/) { 
	    s/[^0-9.]*//g; 
	    $PUBLIC_IP = $_; 
        }
    }
    system("rm index.html");
}


sub set_local_ip {
    my $sock = IO::Socket::INET->new(
        Proto => 'udp',
        PeerAddr => '8.8.8.8',
        PeerPort => '53',
    );
    $LOCAL_IP = $sock->sockhost;
}

sub create_sock {
    my $target = shift;
    my $port = shift;
    my $proto = shift || 'tcp';
    my $interface_ip = $LOCAL_IP;
    my $sock = IO::Socket::INET->new(
	PeerAddr  =>   $target,
        PeerPort   =>   $port,
        Proto      =>   $proto,
	Timeout    =>   1,
    );
    if (!$sock && $DEBUG) {
	foreach ($@) {
	    print "$_\n";
	}
    }    
    return $sock;
}

sub is_alive {
    my $host = shift || 'localhost';
    my $ret_val;
    my $p = Net::Ping->new("icmp");
    $p->bind($LOCAL_IP);
    if ($p->ping($host, 2)) {
        print "\n*** $host is reachable. ***\n";
        $ret_val = 1;
    } else {
        print "\n$host is NOT reachable.\n";
        $ret_val = 0;
    }
    $p->close();
    return $ret_val;
}

sub port_scan {
    my $target = shift || print "Error: no target provided for port scan on $target\n";
    my $sock;
    my @open_ports;
    print "Scanning first $MAX_PORT ports on target $target\n";
    for (my $port=10000; $port <= $MAX_PORT; $port++) {
        $sock = create_sock($target, $port);
        if (!$sock) {
	    if ($DEBUG) {
                print "\nCannot connect on port $port\n";
	    } elsif (!$DEBUG) {
                print STDERR ".";
                next;
	    }
        } else {
            print "\nCan connect to $target:$port\n";
	    push(@open_ports, $port);
            close($sock);
        }
    }
    print "\nOpen ports detected on target $target:\n   " . join("\n   ", @open_ports) . "\n" if @open_ports;
}

sub usage {
    my $usage = "usage: scan.pl [ip address] [-p]\n".
               "\tIf you do not provide a first argument at all the scan will be on localhost.\n".
               "\tThe ip address can be a singular ip address or a network ip address. (i.e. 192.168.1.0)\n".
               "\tIf the -p flag is provided a port scan of the first $MAX_PORT ports\n";

    return $usage;
}

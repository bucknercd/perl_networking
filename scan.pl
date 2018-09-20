#!/usr/bin/perl -w

#Filename: scan.pl

use IO::Socket::INET;
#use lib '/home/chris/cpan/lib/';
use Net::Ping;

#### MAIN ####
my $target = shift || 'localhost';
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


sub create_sock {
    my $target = shift;
    my $port = shift;
    my $proto = shift || 'tcp';
    my $sock = IO::Socket::INET->new(
        PeerAddr   =>   $target,
        PeerPort   =>   $port,
        Proto      =>   $proto
        );
    return $sock;
}

sub is_alive {
    my $host = shift || 'localhost';
    my $ret_val;
    $p = Net::Ping->new();
    if ($p->ping($host)) {
        print "*** $host is alive. ***\n";
        $ret_val = 1;
    } else {
        print "$host is dead.\n";
        $ret_val = 0;
    }
    $p->close();
    return $ret_val;
}

sub port_scan {
    my $target = shift || print "Error: no target provided for port scan on $target\n";
    my $sock;
    my @open_ports;
    print "Scanning first 8000 ports on target $target\n";
    my $j = 0;
    for (my $i=0; $i < 10000; $i++) {
        $sock = create_sock($target, $i);
        if (!$sock) {
            #print "Cannot connect on port $i\n";
            #print".";
            next;
        } else {
            print "\nCan connect to $target:$i\n";
            $open_ports[$j] = $i;
            $j++;
            close($sock);
        }
    }
    print "\nOpen ports detected on target $target:\n   " . join("\n   ", @open_ports) . "\n" if @open_ports;
}






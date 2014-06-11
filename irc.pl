#! /usr/bin/perl


# The principle goal here is to look for botnets and/or possibly
# warez channels.  Botnets where the server is off-capus in general
# can be recognized by a channel having TOO MANY non-server hosts
# doing scanning (the max TCP wormweight is too high).  Botnets where
# the server is off-campus are so obvious statistically that it is somewhat
# embarrasing.  Often the related RRD irc message count graph will show
# their existance.  The evil channel sort MAY short their existance
# which is somewhat odd.  In general a local campus "evil" botserver
# (irc used for remote scanning, infection, etc) reveals itself by
# a ridiculous number of IPs in the channel (else what fun would it be
# for a hacker?).  Other simple statistics like joins, pings, pongs,
# and privmsg counts will be unusually high.  In fact it is possible
# that a botserver might simply be the busiest server in a campus in
# terms of basic TCP message counts.


use vars qw/ %opt /;
use Getopt::Long;

my %hosts = ();
my $directory="";
my $TRUE = 1;
my $FALSE = 0;
my $DEBUG = $FALSE;
my $HTML = $FALSE;
my $delimiter = "\n";
# log a message in the event log if an irc channel has > these hosts
# it may indicate a botnet server (or a really bad botnet client set)
my $K_ipcount = 150;                # MAGIC heuristic Konstant
# log a message in the event log if an irc channel has this many
# "mal" (work weight too high) hosts in it.
my $K_badips = 10;                # if this number of more

my $dochanmerge = 1;                # may turn this off, on by default

# consider a host wormy if the max ww is greater than this number
# this needs to be a running average (so as to leave out email servers)
# but it is not at this point.  email servers do not often do irc
# but that is not foolproof.  this is used in the evil channel calculation.
my $K_wormThreshold = 60;        # MAGIC heuristic Konstant

if ( (scalar @ARGV) < 1 ) {
        printUsageAndExit();
}

GetOptions(
        "h" => \$opt{help},
        "h" => \$opt{h},
        "html" => \$opt{html},
        "debug" => \$opt{debug},
        "d:s" => \$opt{d},
        "B:s" => \$opt{B},
        "e:s" => \$opt{e},
        "f:s" => \$opt{f},
        "w:i" => \$opt{w},                # ips per channel event number
        "m" => \$opt{m},                # turn default channel merge off
);

$eventflag = 0;
$eventfile = "";
if ( $opt{'e'} ) {
        $eventfile = $opt{'e'};
        $eventflag = 1;
}

# override ips/channel event log message number
if ( $opt{'w'} ) {
        $K_ipcount = $opt{'w'};                # MAGIC heuristic Konstant
        #print "$K_ipcount\n";
}

# turn default channel merge off
if ( $opt{'m'} ) {
        $dochanmerge = 0;
}

if ( $opt{'h'} ) {
        printUsageAndExit();
        exit(1);
}

$blacklistflag = 0;
if ( $opt{'B'} ) {
        $blacklistflag = 1;
        $ccdbfile = $opt{'B'};
        dbmopen(%map, $ccdbfile, 0666);
}


if ( $opt{'d'} ) {
        $directory = $opt{'d'};

        #
        # read all files in a directory into the array and
        # prepend directory path to filename
        #
        opendir (DIR, $directory) or
            die "can't open $directory directory: $!\n";
        @FILES = readdir DIR;
        closedir DIR;
        $ninstances = $size = scalar @FILES;
        while ($size > -1) {
                # prepend directory path to files
                if ( -f "$directory/$FILES[$size]" ) {
                        $FILES[$size] = $directory.'/'.$FILES[$size];
                }
                $size--;
        }
}
if ( $opt{'f'} ) {
        @FILES = split / /, $opt{'f'};
        $ninstances = scalar @FILES;
}
# this is the feature that does not exist
# TBD
#if ( $opt{'html'} ) {
#        $HTML = $TRUE;
#}
if ( $opt{'debug'} ) {
        $DEBUG = $TRUE;
}

# files are now in FILES array
# loop thru them
#
my $mode = 0;

while ( $_ = shift @FILES ) {
        my $fname;

        open(FILE, $_) || die "can't open $_ file: $!\n";
        @FILE = <FILE>;
        close(FILE);

        $fname = `basename $_`;
        chomp $fname;

        $phrases = join("<br>",@FILE);

        #  fetch each line from datafile, line is separated by "\n"

        @phrases = split(/$delimiter/,$phrases);

        # walk phrases and process on line by line basis
        # one subroutine per filter type

        foreach my $elem (@phrases) {

                # get rid off blanks, return, line breaks

                $elem =~ s/\n//g;
                $elem =~ s/<br>//g;
                $elem =~ s/ //g;

                # save each item to array @items, from each line,

                @items = split(/:/,$elem);

                # means a comment or a meta-command
                # either in host tuple mode or channel tuple mode
                 if ($items[0] eq "#IRCNODE") {
                        $mode = 1;
                            next;
                 }
                 elsif ($items[0] eq "#IRCCHANNEL") {
                        $mode = 2;
                            next;
                 }
                elsif($mode < 2 && $items[0] =~ /^#./){
                            next;
                }

                #changed: jan 2006, added sampled src/dst port
                #ipsrc:totalmsg:joins:pings:pongs:privmsgs:
                #joinsrc:joindst:pingsrc:pingdst:pongsrc:pongdst:
                #pmsrc:pmdst:channels:serverhits:workweight:sport:dport
                #
                #131.252.208.55:98:0:9:9:80:0:0:0:9:9:0:75:5:1:80:
                if ($mode == 1) {
#                        print "1: $items[0]\n";
                        $ipsrc = $items[0];
                        # perform db lookup if -B set
                        if ($blacklistflag) {
                                if ($map{$ipsrc}) {
                                        $ircHostCCMaster{$ipsrc}++;
                                }
                        }
                        $ircHostTotalMsg{$ipsrc} += $items[1];
                        $ircHostJoins{$ipsrc} += $items[2];
                        $ircHostPings{$ipsrc} += $items[3];
                        $ircHostPongs{$ipsrc} += $items[4];
                        $ircHostPrivMsgs{$ipsrc} += $items[5];
                        # ignore other fields inbetween for now
                        # calculate max channels for an ipsrc
                        $ircHostChannels{$ipsrc} += $items[14];
                        if ($items[14] > $ircHostMaxChannels{$ipsrc}) {
                                $ircHostMaxChannels{$ipsrc} = $items[14];
                        }
                        $ircHostServerHits{$ipsrc} += $items[15];
                        # keep worst-case value.
                        # adding means we compute the average.
                        $ircHostWorminess{$ipsrc} += $items[16];
                        if ($items[16] > $ircHostMaxWorm{$ipsrc}) {
                                $ircHostMaxWorm{$ipsrc} = $items[16];
                        }
                        # these are just sampled
                        $ircHostsport{$ipsrc} = $items[17];
                        $ircHostdport{$ipsrc} = $items[18];
                }
                #channame:hits:joins:privmsgs:noips:ip list, ip, ip ...
                # channels
                elsif ($mode == 2) {
#                        print "2: $items[0]\n";
                        $origchan = $items[0];
                        # reduce channel name to lower case
                        if ($dochanmerge) {
                                $channel = lc($origchan);

                                # produce a list of names for human
                                # consumption (the ngrep user) that are actually different
                                # we have two associative lists
                                # chanNameMap is the output list of associated names that are unique
                                # chanAllNameMap is a list of all names seen

                                # see if the unchanged channel name is in the AllNameMap, if not, then record it in the list
                                if (!$chanAllNameMap{$origchan}) {
                                        $chanAllNameMap{$origchan} = $origchan;                # put it in
                                        if ( $chanNameMap{$channel} ) {
                                                $chanNameMap{$channel} = $chanNameMap{$channel} . ", " . $origchan;   # add it to the unique mapping list
                                        }
                                        else {
                                                $chanNameMap{$channel} = $origchan;   # add it to the unique mapping list
                                        }
                                }
                        }
                        else {
                                $channel = $origchan;
                        }
                        $ircChanHits{$channel} += $items[1];
                        $ircChanJoins{$channel} += $items[2];
                        $ircChanPrivmsgs{$channel} += $items[3];
                        $ircChanIPCount{$channel} += $items[4];
                        # $chanIPList{$channel} is kept up by this function
                        ipChanListMerge($items[5], $channel, $fname);
                }
        }  # end loop
} # end file loop

globalStats();
chanStats();
hostStats();

if ($blacklistflag) {
        dbmclose(%map);
}

exit;


##########################################################

#
# subroutines
#

#
# global stats
#
#        # instances
#        # total number of irc hosts
#        # total number of irc servers
#        # total number of unique channels
#
# TBD:  later - biggest network?
#        average network size is likely to be 2

sub globalStats
{
        my $c = 0;
        $start_time=`date`;                # start_time is global
        $start_time=~ s/\n//g;

        print "irc summarization at: $start_time\n";

        print "###################################################\nglobal stats:\n";
        print "\t# of sample files: $ninstances\n";
        my $irchosts = keys %ircHostTotalMsg;
        print "\t# of irc hosts (servers and non-servers): $irchosts\n";
        foreach my $ipsrc (keys %ircHostServerHits) {
                if ( $ircHostServerHits{$ipsrc}) {
                        $c++;
                }
        }
        print "\t# of irc servers: $c\n";
        my $uniquechannels =  keys %ircChanHits;
        print "\t# of unique channels: $uniquechannels\n";
}

#
# sort by biggest number of messages
#
# list channels
#        give per channel stats
#
# list channels again but with hosts in channel
#        list hosts in channel with host stats
#
# list subset of channels that are join only
#
sub chanStats
{
        my @wormychannels = undef;
        my $evilchannel = 0;

        print "\n\n###################################################\nchannel stats:\n\n";

        # sort the channels by max messages and list them
        #
        my @Allsortedchans  = sort chanhits_by_value keys(%ircChanHits);

        # now figure out how many worms per channel
        # this is the "evil" channel calculation
        # this calculation has one trick.
        # note: no printing here!  this is a preprocess operation.
        #
        foreach my $channel (@Allsortedchans) {
                $evilchannel = "";
                # first get the host count and host list
                my @iplist = split(",", $chanIPList{$channel});
                my $ipcount = @iplist;
                my $wormcount = 0;
                my $servercount = 0;
                foreach $host (@iplist) {
                        # get the worm count for this host
                        my $maxworm = $ircHostMaxWorm{$host};
                        if ($maxworm >= $K_wormThreshold) {
                                $wormcount++;
                        }
                        if ( $ircHostServerHits{$host} ) {
                                $servercount++;
                        }
                }
                my $totalhosts = $ipcount - $servercount;
                # now we have total ip count
                #             total worm count
                #              total server count
                #              total host count
                #
                # if half of the total hosts are wormy
                # if half of the total hosts discounting servers are wormy
                if ( $wormcount > 0 && (($wormcount >= ($ipcount / 2)) || ($wormcount >= (totalhosts / 2)))) {
                        $evilchannel = E;
                        if ($wormcount == 1) {
                                $evilchannel = e;
                        }
                }
                #if ( $wormcount > 0 && ($wormcount >= ($totalhosts / 2))) {
                #        $evilchannel = E;
                #}
                $chanEviltude{$channel} = $evilchannel;
                $chanWormCount{$channel} = $wormcount;
        }

        my @Allevilchans  = sort chan_by_evil keys(%chanWormCount);
        print "channels sorted by evil factor: max number of wormy hosts:\n";
        print "\tchannel                              msgs      joins   privmsgs    ipcount wormyhosts      evil?\n";
        foreach my $channel (@Allevilchans) {
                if ($chanWormCount{$channel} > $K_badips) {
                        if ($eventflag) {
                                my $s =
"botnet client mesh?: irc channel $channel has bad #hosts: ";
                                storeEvent($eventfile, $s, $chanWormCount{channel});
                        }
                }
                if ($chanWormCount{$channel} == 0) {
                        last;
                }
                my @iplist = split(",", $chanIPList{$channel});
                my $ipcount = @iplist;
                my $sbuf = sprintf("%-30.30s %10d %10d %10d %10d %10d      %s",
                        $channel, $ircChanHits{$channel}, $ircChanJoins{$channel}, $ircChanPrivmsgs{$channel}, $ipcount, $chanWormCount{$channel}, $chanEviltude{$channel});
                print "\t$sbuf\n";
        }

        print "\nchannels sorted by max messages (note e/E for possible evil channel):\n";
        print "\tchannel                              msgs      joins   privmsgs    ipcount wormyhosts      evil?\n";
        foreach my $channel (@Allsortedchans) {
                my @iplist = split(",", $chanIPList{$channel});
                my $ipcount = @iplist;
                # if too many ips in channel, possible botserver
                if ($ipcount > $K_ipcount) {
                        if ($eventflag) {
                                my $s = "botserver?: irc channel $channel has #hosts: ";
                                storeEvent($eventfile,$s, $ipcount);
                        }
                }
                my $sbuf = sprintf("%-30.30s %10d %10d %10d %10d %10d      %s",
                        $channel, $ircChanHits{$channel}, $ircChanJoins{$channel}, $ircChanPrivmsgs{$channel}, $ipcount, $chanWormCount{$channel}, $chanEviltude{$channel});
                print "\t$sbuf\n";
        }

        # now list the channels with host stats
        print "\nchannels with per host stats:\n";
        print "\tchannel\n\t\tip_src                 tmsg  tjoin  tping  tpong tprivmsg maxchans maxworm Server? sport/dport first_ts\n";
        foreach $channel (@Allsortedchans) {
                $sbuf = sprintf("%-30.30s", $channel);
                print "\t$sbuf\n";

                my @iplist = split(",", $chanIPList{$channel});
                my $newchan = 0;
                foreach $host (@iplist) {
                        # are we a server or a host
                        if ( $ircHostServerHits{$host} ) {
                                $sflag = "S";
                        }
                        else {
                                $sflag = "H";
                        }
                        my $tmsg = $ircHostTotalMsg{$host};
                        my $tjoin = $ircHostJoins{$host};
                        my $tping = $ircHostPings{$host};
                        my $tpong = $ircHostPongs{$host};
                        my $tprivmsg = $ircHostPrivMsgs{$host};
                        my $maxchan = $ircHostMaxChannels{$host};
                        my $maxworm = $ircHostMaxWorm{$host};
                        my $sport = $ircHostsport{$host};
                        my $dport = $ircHostdport{$host};
                        my $pstring = $sport . "/" . $dport;
                        if (($maxworm >= $K_wormThreshold) && ($newchan == 0)) {
                                push @wormychannels, $channel;
                                $newchan = 1;
                        }
                        my $myindex = join("/", $channel, $host);
                        $sbuf = sprintf("%-20.20s %6d %6d %6d %6d %8d %8d %6d %6s %13s %s",
                                $host, $tmsg, $tjoin, $tping, $tpong, $tprivmsg, $maxchan, $maxworm, $sflag, $pstring,
                                        $channelIPts{$myindex} );
                        print "\t\t$sbuf\n";
                }
        }

        # list channels that only have join messages
        print "\nchannels with no privmsgs, only joins:\n";
        print "\tchannel                              msgs      joins   privmsgs    ipcount\n";
        foreach $channel (@Allsortedchans) {
                if ($ircChanJoins{$channel} == $ircChanHits{$channel}) {
                        my @iplist = split(",", $chanIPList{$channel});
                        my $ipcount = @iplist;
                        my $sbuf = sprintf("%-30.30s %10d %10d %10d %10d",
                                $channel, $ircChanHits{$channel}, $ircChanJoins{$channel}, $ircChanPrivmsgs{$channel}, $ipcount);
                        print "\t$sbuf\n";
                }
        }

        # list channels that seem to be wormy where we define wormy
        # as any channel with one host greater than the K_wormThreshold
        print "\nchannels with ANY hosts with non-zero possibly wormy work metric (> $K_wormThreshold%):\n";
        print "\tchannel";
        foreach $channel (@wormychannels) {
                print "\t$channel\n";
        }

        # list the channel name map: key is lowercase name, then list
        # of names actually seen in the wild.
        print "\nchanmap table: case insensitive channel name to chan names seen in real world:\n";
        foreach my $channel (keys %chanNameMap) {
                print "\t$channel: $chanNameMap{$channel}\n";
        }
}

#
# hostStats
#
# list servers - busy to not busy
# TBD: list "our" servers
#
# list subset of hosts that are join only
#
# list subset of hosts that have any AVERAGE worminess
#

sub hostStats
{
        print "\n\n###################################################\nirc host stats:\n";
        # list servers
        #
        my @Allsortedhosts  = sort hosthits_by_value keys(%ircHostTotalMsg);

        print "servers sorted by max messages\n";
        print "\tip_src                 tmsg  tjoin  tping  tpong tprivmsg maxchans maxworm\n";
        foreach my $host (@Allsortedhosts) {
                if ( $ircHostServerHits{$host} ) {
                        my $tmsg = $ircHostTotalMsg{$host};
                        my $tjoin = $ircHostJoins{$host};
                        my $tping = $ircHostPings{$host};
                        my $tpong = $ircHostPongs{$host};
                        my $tprivmsg = $ircHostPrivMsgs{$host};
                        my $maxchan = $ircHostMaxChannels{$host};
                        my $maxworm = $ircHostMaxWorm{$host};
                        $sbuf = sprintf("%-20.20s %6d %6d %6d %6d %8d %8d %6d",
                                $host, $tmsg, $tjoin, $tping, $tpong, $tprivmsg, $maxchan, $maxworm);
                        print "\t$sbuf\n";
                }
        }

        # list hosts that are join only with no privmsg
        print "\nhosts with join msgs but no privmsgs\n";
        print "\tip_src                 tmsg  tjoin  tping  tpong tprivmsg maxchans maxworm\n";
        foreach my $host (@Allsortedhosts) {
                my $tjoin = $ircHostJoins{$host};
                my $tprivmsg = $ircHostPrivMsgs{$host};

                if (($tprivmsg == 0) && ($tjoin > 0)) {
                        my $tmsg = $ircHostTotalMsg{$host};
                        my $tjoin = $ircHostJoins{$host};
                        my $tping = $ircHostPings{$host};
                        my $tpong = $ircHostPongs{$host};
                        my $tprivmsg = $ircHostPrivMsgs{$host};
                        my $maxchan = $ircHostMaxChannels{$host};
                        my $maxworm = $ircHostMaxWorm{$host};
                        $sbuf = sprintf("%-20.20s %6d %6d %6d %6d %8d %8d %6d",
                                $host, $tmsg, $tjoin, $tping, $tpong, $tprivmsg, $maxchan, $maxworm);
                        print "\t$sbuf\n";
                }
        }

        # list hosts that have shown any signs of worminess
        print "\nhosts with any signs of worminess with any instance of work >= $K_wormThreshold%\n";
        print "\tip_src                 tmsg  tjoin  tping  tpong tprivmsg maxchans maxworm\n";
        foreach my $host (@Allsortedhosts) {

                my $maxworm = $ircHostMaxWorm{$host};
                if ($maxworm >= $K_wormThreshold) {
                        my $tmsg = $ircHostTotalMsg{$host};
                        my $tjoin = $ircHostJoins{$host};
                        my $tping = $ircHostPings{$host};
                        my $tpong = $ircHostPongs{$host};
                        my $tprivmsg = $ircHostPrivMsgs{$host};
                        my $maxchan = $ircHostMaxChannels{$host};
                        $sbuf = sprintf("%-20.20s %6d %6d %6d %6d %8d %8d %6d",
                                $host, $tmsg, $tjoin, $tping, $tpong, $tprivmsg, $maxchan, $maxworm);
                        print "\t$sbuf\n";
                }
        }
        # list hosts that were put in blacklist so
        # the end of the report can be of interest too
        if ($blacklistflag) {
                print "\nhosts appear in blacklist!!! - assume channel is infected\n";
                print "\tip_src                 hits\n";
                foreach my $ipsrc (keys %ircHostCCMaster) {
                        my $sbuf = sprintf("%-20.20s %6d", $ipsrc, $ircHostCCMaster{$ipsrc});
                        # irc event to go into event log
                        # ok if this appears over and over again for the day
                        storeEvent($eventfile, "irc blacklist hit for (ip/count):", $sbuf);
                        print "\t$sbuf\n";
                }
        }
}


sub printUsageAndExit()
{
        print "Usage: perl $0 options\n";
        print "     -h            displays usage\n";
        print "     -e eventfile  event file for event logging\n";
        print "     -d directory  directory of mon.lite files\n";
        print "     -f file1 file2 ... fileN list of files to read\n";
        print "     -html         produce HTML output (not implemented)\n";
        print "     -debug        produce debugging columns\n";
        print "     -w N          reset #of IPS per channel bot server event constant (default 150) \n";
        print "     -m            turn default channel merge off\n";
        print "     -B blacklist  take db file with known bad ips and include in report if spotted\n";
        exit;
}

#
# merge ip list into one unique list
#
# global:
#        $chanIPList{$channel}
sub ipChanListMerge
{
        my $newips = $_[0];
        my $channel = $_[1];
        my $file = $_[2];

        my @newiplist = split(",", $newips);
        my @oldiplist = split(",", $chanIPList{$channel});

        my $last = undef;
        my @new = grep { ($last ne $_) && ($last = $_) } sort(@newiplist, @oldiplist);

        $chanIPList{$channel} = join(",", @new);

        my @iplist = split(",", $chanIPList{$channel});
        foreach $host (@iplist) {
                $myindex = join("/", $channel, $host);
                # $channel, $host
                if ($channelIPts{$myindex}) {
                        ; # do nothing as it exists
                }
                else {
                        $channelIPts{$myindex} = $file;        # store (channel, IP), first file seen (timestamp)
#print "GOOBER: $myindex, $fname\n";
                }
        }

#        print "$channel: $chanIPList{$channel}\n";
}

sub chanhits_by_value
{
        if ($ircChanHits{$a} < $ircChanHits{$b}) {
                1;
        }
        elsif ($ircChanHits{$a} == $ircChanHits{$b}) {
                0;
        }
        elsif ($ircChanHits{$a} > $ircChanHits{$b}) {
                -1;
        }
}

sub chan_by_evil
{
        if ($chanWormCount{$a} < $chanWormCount{$b}) {
                1;
        }
        elsif ($chanWormCount{$a} == $chanWormCount{$b}) {
                0;
        }
        elsif ($chanWormCount{$a} > $chanWormCount{$b}) {
                -1;
        }
}

sub hosthits_by_value
{
        if ($ircHostTotalMsg{$a} < $ircHostTotalMsg{$b}) {
                1;
        }
        elsif ($ircHostTotalMsg{$a} == $ircHostTotalMsg{$b}) {
                0;
        }
        elsif ($ircHostTotalMsg{$a} > $ircHostTotalMsg{$b}) {
                -1;
        }
}

# storeEvent($eventfile, "new worm signature from:", $sbuf);
#
# storeEvent(file, prependString, eventString)
#
# eventString may or may not have a newline.  we strip it if it does.
#
sub
storeEvent
{

        if ($eventflag == 0) {
                return;
        }
        my $eventfile = $_[0];
        my $prependString = $_[1];
        my $eventString = $_[2];
        my $s;

        $eventString=~ s/\n//g;
        $s = "$start_time: " . $prependString . $eventString;

         open(FILE, ">>$eventfile") || die "can't open $eventfile: $!\n";
         print FILE "$s\n";
         close(FILE);
}
exit;
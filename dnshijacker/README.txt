[ dns hijacker v1.3 ]

pedram amini (pedram@redhive.com)
pedram.redhive.com

Table of Contents:
    - Introduction
    - Uses
    - Compiling
    - Command Line Options
    - The Fabrication Table
    - Extras
    - Brief Technical Rundown
    - How To Remove Ads
    - How To Use With RRDtool


/**************************************
 *  Introduction                      *
 **************************************/

Inspired by an idea I came up with while sitting on the john I set out to write
a program that would sniff dns requests and spoof answers. 800 lines of code and
25 hours later I had given birth to dnshijacker.

The following is a run-down on what it can do, and how you can go about doing
it.


/**************************************
 *  Uses                              *
 **************************************/

Aside from the tremendous comical value of redirecting your friends to gay porno
sites there are a few other (possibly legitimate) uses to dnshijacker. Firstly,
sites can be filtered based on keywords in domain names. Of course this can
easily be bypassed through the usage of a proxy. The second, and in my opinion,
more useful use is to hijack the queries for all the popular ad servers (such as
doubleclick.net). That way not only are you alleviating yourself from the
ghastly sight of advertisements, but you've also upped your level of privacy a
notch or two.

Along with the prankster, the blackhat will probably find the most uses for
dnshijacker. the possibilities are endless. One could easily mirror a site
(hotmail, etrade, online banking, etc) and redirect requests to that mirror for
login/password collection. Another target for attack is the auto-update features
that most windows applications use. Next time Winamp or AOL Instant Messenger
check for an update, the request can be redirected to yourself, an "update
available" answer can then be spoofed, and a trojan wrapped executable sent to
the victim.


/**************************************
 *  Compiling                         *
 **************************************/

dnshijacker was built and tested on an x86 running redhat linux 7.3 it requires
libpcap (www.tcpdump.org) and libnet (www.packetfactory.net), at the time I was
using versions 0.7.1 and 1.1.0 respectively. To compile:

	gcc dnshijacker.c -lpcap -lnet `libnet-config --defines` -o dnshijacker

You can optionally compile with -DDEBUG to enable (messy) debug messages. You
could also check out the Makefile.


/**************************************
 *  Command Line Options              *
 **************************************/

-d <ip address>
You can set the default answer that dnshijacker will respond with using the -d
switch followed by an ip address in normal dotted quad form (xxx.xxx.xxx.xxx).
dnshijacker will use the default address in the case that no match is found for
the current question in the fabrication table or if no fabrication table is
present to begin with.

-f <filename>
The -f switch is used to point dnshijacker to the location of your custom
fabrication table. The file must be readable, see below for a guide to the
fabrication table.

-i <interface>
Specify the interface to work on. Pretty simple.

-p
The -p switch puts dnshijacker into print only mode. I use this when I just want
to take a look at traffic patterns to build my fabrication table. It was also
useful
during the development/debug stage and I just left it around.

-v
The -v switch will make dnshijacker print more verbose information, basically
this includes all the dnsheader segments.

dnshijacker will also accept an optional tcpdump style filter string. The key to
this is that the program works only on what it can see. This is best explained
by example...

Say I want to only watch dns traffic, but I want to watch traffic both to and
from dns servers. Well in this case the default "udp dst port 53" is not going
to cut it, so we run dnshijacker with:

    dnshijacker -p udp src or dst port 53

What if we wanted to spoof answers, but also wanted to see traffic from dns
servers...

    dnshijacker -f ftable udp src or dst port 53

dnshijacker is smart enough not to attempt to spoof answers to answers. The more
practical usage of the filter however is when you want to only hijack certain
peoples questions. Say for example I only want to hijack johnny's (10.0.0.5)
questions...

    dnshijacker -f ftable udp dst port 53 and src 10.0.0.5

On a final note, when the -f and -d switches are used together obviously the -f
takes precedence. In the case that a match is not found then dnshijacker will
fall back to
using the default address.


/**************************************
 *  The Fabrication Table             *
 **************************************/

The fabrication table is in the standard /etc/hosts format. Probably the best 
way to explain the format would be by example. So, say for instance you want 
hijack all requests for www.microsoft.com and redirect them to www.apple.com 
(17.254.0.91). The table entry would read:

17.254.0.91     www.microsoft.com            # answer = apple.com

Remember that anything past the second column is a comment. What if we want to
also redirect secure.microsoft.com www.insecure.org (208.184.74.98)? ...

17.254.0.91     www.microsoft.com            # www.apple.com
208.184.74.98   secure.microsoft.com         # www.insecure.org

Lastly, say we wanted to redirect <anything>.microsoft.com to www.apple.com...

17.254.0.91     microsoft.com                # www.apple.com

This works because our table entries represent the needle, and the dns question
is the haystack. So as long as the needle exists somewhere within the haystack a
match exists.

The maximum number of entries is currently 500. If you need more then that,
change the define in the header file and recompile.


/**************************************
 *  Extras                            *
 **************************************/

Also included in the package are 2 programs ask_dns and answer_dns. These were
used during development/debugging, but I figured someone may find them useful so
I left them in here. ask_dns surprisingly will ask a dns question:

	ask_dns <source_ip> <port> <destination_ip> <port> <dns_id>

answer_dns will write a dns answer. This is actually more useful then ask_dns in
that it can be used to spoof an answer to someone not on your lan. Of course you
need to be able to guess when the victim is looking up the name that you wish to
hijack and what the dns id will be. answer_dns will write <#_packets> packets
and increment <dns_id> by one each time (easing the burden of guessing the id).

	answer_dns <source_ip> <port> <destination_ip> <port> <dns_id> <#_packets>

Both programs use static data, that can easily be changed however by using
dnshijacker's source as a guide.


/**************************************
 *  Brief Technical Rundown           *
 **************************************/

dnshijacker uses the libpcap interface for packet capturing. The program starts
off by initializing the capture device through this interface. Once this and
other initialization is complete dnshijacker falls into an infinite packet
capturing loop.

Each captured packet is passed to parse_dns(), which first checks to make sure
we can use this packet and then steps through the packet and pulls out all
relevant/necessary information. parse_dns() is also responsible for building the
payload of the answer we are going to spoof. It does so by first calling
search_table(), which will search through the user specified fabrication table
and return (if any) the appropriate answer. Armed with this information
parse_dns() will complete the construction of the payload. All information
generated by parse_dns() is stored in our globally declared structure
chewy_center.

The next step is to make sure we want to spoof an answer. First we check if the
print only flag is on, if not we call spoof_dns() and pass to it the socket on
which we wish to write. spoof_dns() will check a few more conditions before
attempting to do anything, if the conditions pass then we will begin
constructing our spoof packet. This is all done through libnet's raw socket API.
spoof_dns() builds the packet headers from information stored in
chewy_center, it then tacks on the payload and writes the packet.


/**************************************
 *  How To Remove Ads                 *
 **************************************/

The default ftable comes with an extensive list of ad servers gleaned from
http://www.yoyo.org/~pgl/adservers/. The entries are by default mapped to
localhost (127.0.0.1). While this does successfully block advertisements it
leaves broken images and causes problems in some browsers (Netscape). The
following is a description of the three step approach I took to remove ads from
my home network:

1. First you need to alias an unused IP address on one of your interfaces. This
will serve as the address that we redirect all ad servers to. I chose 10.0.0.3.

2. Next you need to modify the ftable replacing all 127.0.0.1'1 with 10.0.0.3.

3. Finally you need to setup an Apache virtual host with a mod_rewrite rule that
redirects all requests to an image of your choosing. I created a 1x1 transparent
GIF for this purpose. Here is a sample virtual host entry to get you started:

<VirtualHost 10.0.0.3>
    ServerAdmin   admin@my.server.com
    DocumentRoot  /path/to/my/vhost
    ServerName    no-ads.my.server.com
    ErrorLog      /dev/null
    CustomLog     /dev/null common
    RewriteEngine on
    RewriteRule   ^.* /spacer.gif
</VirtualHost>


/**************************************
 *  How To Use With RRDtool           *
 **************************************/
 
First and foremost you need to create a round robin database to store your
statistic values in. I choose to keep one weeks worth of 10 minute samples:

    rrdtool create dnshijacker.rrd      \
            --step 600                  \
            DS:spoofs:COUNTER:1200:U:U  \
            RRA:AVERAGE:0.5:1:1008

You then need to collect statistics. I use the following perl snippet which is
called from cron every ten minutes:

    #!/usr/bin/perl
    
    #
    # dnshijacker spoof count rrd collector
    #
    
    $print_flag = shift;
    
    $num_spoofs = int(`cat /var/log/dnshijacker_spoofs`);
    
    if ($print_flag)    {
        print "rrdtool update /rrd/dnshijacker.rrd N:$num_spoofs\n";
    }
    
    `rrdtool update /rrd/dnshijacker.rrd N:$num_spoofs`;

You finally need to graph your statistics. I use the following shell script
which is called from cron every hour:

    #!/bin/bash
    
    ###
    # cron.daily script
    # recreates daily and weekly dnshijacker spoof statistics graphs.
    # rrd database location: /rrd/
    # rrd graph location:    /www/html/rrdgraphs/
    
    
    rrdtool graph /www/html/rrdgraphs/dnshijacks_daily.gif   \
            --title "1-day dnshijacks"                       \
            --width 600                                      \
            --color BACK#333333                              \
            --color SHADEA#000000                            \
            --color SHADEB#000000                            \
            --color CANVAS#000000                            \
            --color GRID#999999                              \
            --color MGRID#666666                             \
            --color FONT#CCCCCC                              \
            --color FRAME#333333                             \
            --start -86400                                   \
            --vertical-label "spoofed answers"               \
            --no-legend                                      \
            --units-exponent 0                               \
            DEF:ns=/rrd/dnshijacker.rrd:spoofs:AVERAGE       \
            AREA:ns#0066FF                                   \
            LINE1:ns#FF0000
            
    rrdtool graph /www/html/rrdgraphs/dnshijacks_weekly.gif  \
            --title "1-week dnshijacks"                      \
            --width 600                                      \
            --color BACK#333333                              \
            --color SHADEA#000000                            \
            --color SHADEB#000000                            \
            --color CANVAS#000000                            \
            --color GRID#999999                              \
            --color MGRID#666666                             \
            --color FONT#CCCCCC                              \
            --color FRAME#333333                             \
            --start -604800                                  \
            --vertical-label "spoofed answers"               \
            --no-legend                                      \
            --units-exponent 0                               \
            DEF:ns=/rrd/dnshijacker.rrd:spoofs:AVERAGE       \
            AREA:ns#0066FF                                   \
            LINE1:ns#FF0000
            #!/bin/bash

###
# cron.daily script
# recreates daily and weekly dnshijacker spoof statistics graphs.
# rrd database location: /rrd/
# rrd graph location:    /www/html/rrdgraphs/


rrdtool graph /www/html/rrdgraphs/dnshijacks_daily.gif   \
        --title "1-day dnshijacks"                       \
        --width 600                                      \
        --color BACK#333333                              \
        --color SHADEA#000000                            \
        --color SHADEB#000000                            \
        --color CANVAS#000000                            \
        --color GRID#999999                              \
        --color MGRID#666666                             \
        --color FONT#CCCCCC                              \
        --color FRAME#333333                             \
        --start -86400                                   \
        --vertical-label "spoofed answers"               \
        --no-legend                                      \
        --units-exponent 0                               \
        DEF:ns=/rrd/dnshijacker.rrd:spoofs:AVERAGE       \
        AREA:ns#0066FF                                   \
        LINE1:ns#FF0000
        
rrdtool graph /www/html/rrdgraphs/dnshijacks_weekly.gif  \
        --title "1-week dnshijacks"                      \
        --width 600                                      \
        --color BACK#333333                              \
        --color SHADEA#000000                            \
        --color SHADEB#000000                            \
        --color CANVAS#000000                            \
        --color GRID#999999                              \
        --color MGRID#666666                             \
        --color FONT#CCCCCC                              \
        --color FRAME#333333                             \
        --start -604800                                  \
        --vertical-label "spoofed answers"               \
        --no-legend                                      \
        --units-exponent 0                               \
        DEF:ns=/rrd/dnshijacker.rrd:spoofs:AVERAGE       \
        AREA:ns#0066FF                                   \
        LINE1:ns#FF0000

![sybilhunter logo](https://nullhypothesis.github.com/sybilhunter_logo.png)
===========================================================================

[![Build Status](https://travis-ci.org/NullHypothesis/sybilhunter.svg?branch=master)](https://travis-ci.org/NullHypothesis/sybilhunter)

Overview
--------
Sybilhunter is a command line tool written in [Go](https://golang.org) to
discover and analyse Sybil relays in the Tor network.  It does so by
implementing a number of analysis techniques that take as input [archived Tor
network data](https://collector.torproject.org).  For example, sybilhunter can
tell you (*i*) when an unusally large amount of relays joined or left the Tor
network, (*ii*) which Tor relays changed their identity keys a lot, and (*iii*)
which Tor relays are configured very similar to each other.  Ideally,
sybilhunter should become a Swiss Army knife for analysing anomalies in network
consensuses and relay descriptors.  The theory behind sybilhunter is discussed
in a [research paper](https://nymity.ch/sybilhunting/) that was published at the
[USENIX Security
2016](https://www.usenix.org/conference/usenixsecurity16/technical-sessions/presentation/winter)
conference.

Get started in 5 minutes
------------------------
Assuming you have a working Go installation, this is how you can get started:

    $ go get github.com/NullHypothesis/sybilhunter
    $ wget https://collector.torproject.org/archive/relay-descriptors/consensuses/consensuses-2015-08.tar.xz
    $ tar xvJf consensuses-2015-08.tar.xz
    $ sybilhunter -data consensuses-2015-08 -print

Now you have one month worth of consensuses and can proceed to the next section
to learn more about analysis examples.

Examples
--------
Sybilhunter takes as input data obtained from
[CollecTor](https://collector.torproject.org).  Let's start by pretty-printing
a file containing a network consensus or relay descriptors:

    $ sybilhunter -data /path/to/file -print

Next, here's how you can analyse how often relays changed their fingerprint in
a set of consensus documents:

    $ sybilhunter -data /path/to/consensuses/ -fingerprints

Sybilhunter is also able to create uptime images, visualising the uptime of
relays over time.  In such an image, every column is a relay and every row is a
consensus.  Each pixel is either black (relay was offline) or white (relay was
online).  Red blocks are adjacent relays with identical uptime.  You can create
an uptime image by running:

    $ sybilhunter -data /path/to/consensuses/ -uptime

Sybilhunter then writes an image like the following to disk:

![uptime image](https://nullhypothesis.github.com/uptimes-thumb.jpg)

You can also put command line arguments into the configuration file
`~/.sybilhunterrc`.  The format is just like command line arguments, one per
line.  For example:

    $ cat ~/.sybilhunterrc
    -descdir /path/to/server/descriptors/
    -referencerelay 9B94CD0B7B8057EAF21BA7F023B7A1C8CA9CE645

Note that command line arguments overwrite the arguments in the configuration
file.

Alternatives
------------

Check out [doctor](https://gitweb.torproject.org/doctor.git/)'s [sybil
checker](https://gitweb.torproject.org/doctor.git/tree/sybil_checker.py)
script, and [hstools](https://github.com/FiloSottile/hstools) can be useful
for finding anomalies in hidden service directories.

Contact
-------
For bugs and requests, please file a ticket in [The Tor Project's bug
tracker](https://bugs.torproject.org).  You can also contact me privately:

Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`

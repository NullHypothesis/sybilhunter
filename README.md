![sybilhunter logo](https://nullhypothesis.github.com/sybilhunter_logo.png)
===========================================================================

[![Build Status](https://travis-ci.org/NullHypothesis/sybilhunter.svg?branch=master)](https://travis-ci.org/NullHypothesis/sybilhunter)

Overview
--------
`sybilhunter` implements a number of analysis techniques to find Sybils and
other anomalies in [archived Tor network
data](https://collector.torproject.org).  For example, `sybilhunter` can tell
you when an unusally high amount of relays joined or left the Tor network,
which Tor relays changed their identity keys a lot, and which Tor relays appear
to be very similar to each other.  Ideally, `sybilhunter` should become a Swiss
Army knife for analysing anomalies in network consensuses and relay
descriptors.

Get started in 5 minutes
------------------------
Assuming you have a working Go installation:

    $ go get github.com/NullHypothesis/sybilhunter
    $ wget https://collector.torproject.org/archive/relay-descriptors/consensuses/consensuses-2015-08.tar.xz
    $ tar xvJf consensuses-2015-08.tar.xz
    $ sybilhunter -data consensuses-2015-08 -print

Now you have one month worth of consensuses and can proceed to the next section
to learn more about analysis examples.

Examples
--------
`sybilhunter` takes as input data obtained from
[CollecTor](https://collector.torproject.org).  Let's start by pretty-printing
a file containing a network consensus or relay descriptors:

    $ sybilhunter -data /path/to/file -print

Next, here's how you can analyse how often relays changed their fingerprint in
a set of consensus documents:

    $ sybilhunter -data /path/to/consensuses/ -fingerprints

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

Check out [`doctor`](https://gitweb.torproject.org/doctor.git/)'s [sybil
checker](https://gitweb.torproject.org/doctor.git/tree/sybil_checker.py)
script, and [`hstools`](https://github.com/FiloSottile/hstools) can be useful
for finding anomalies in hidden service directories.

Contact
-------
For bugs and requests, please file a ticket in [The Tor Project's bug
tracker](https://bugs.torproject.org).  You can also contact me privately:

Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`

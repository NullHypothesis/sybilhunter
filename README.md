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

Examples
--------
`sybilhunter` takes as input data obtained from
[CollecTor](https://collector.torproject.org).  Let's start by pretty-printing
a file containing a network consensus or relay descriptors:

    $ sybilhunter -data /path/to/file -print

Next, here's how you can analyse how often relays changed their fingerprint in
a set of consensus documents:

    $ sybilhunter -data /path/to/consensuses/ -fingerprints

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

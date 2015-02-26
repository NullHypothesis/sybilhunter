Overview
--------
`sybilhunter` hunts for sybils in the Tor anonymity network.

Examples
--------
To analyse consensuses as archived by
[CollecTor](https://collector.torproject.org), run:

    $ sybilhunter -archive /path/to/archived/consensuses/

To see how many fingerprints were used by each relay IP address, run:

    $ sybilhunter -fingerprint /path/to/archived/consensuses/

Alternatives
------------

Check out [`doctor`](https://gitweb.torproject.org/doctor.git/)'s [sybil
checker](https://gitweb.torproject.org/doctor.git/tree/sybil_checker.py) script.

Contact
-------
Contact: Philipp Winter <phw@nymity.ch>  
OpenPGP fingerprint: `B369 E7A2 18FE CEAD EB96  8C73 CF70 89E3 D7FD C0D0`

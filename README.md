# perl_networking
This repo has a perl network scanner. This is a command line tool and will ping host(s) and scan ports 1-10000.
$perl scan --help produces usage.

'connect' is another program that one can use to connect to a server with. Provide no arguments to see usage.
'connect' currently supports only http and dns protocols.

Note: 'scan' must be run as root for it to work since it uses icmp for pings.

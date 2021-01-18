# NETSCAN:

This aplication is composed of a NetworkScanner class that executes a ping sweep for every ping in a Network IP.

This aplication can be used to monitor any new devices or changes in the network as standalone:

$python3 netscan.py [options]

The [options] are all optional and include:

-p  [period]            : The period between each scan in seconds. By default 10.

-n  [Network_IP_addr]   : Network IP in the format of X.X.X.X/mask

-s                      : Performs a single scan instead of a continuos periodic scan

This aplication is also used in the extended SNMP agent netscan.
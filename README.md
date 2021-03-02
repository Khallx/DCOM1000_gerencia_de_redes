# NETSCAN PROJECT

This program was part of the coursework for DCOM1000 gerência de redes class at Universidade Federal de Santa Maria.

There are two different applications: netscan and netscan_MIB_agent. They both run on unix systems.

Required packages:
* Python version 3.6 or greater
* snmpd 
* iproute2

# NETSCAN

This is a simple python script that runs continuosly an reports changes to devices on the network.

# NETSCAN MIB AGENT

This script extends the netscan application and runs a SNMP agent that implements a MIB to inform data gathered. A bash script is available to automatically add the MIB and run the agent.
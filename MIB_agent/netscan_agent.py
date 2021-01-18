# -*- coding: utf-8 -*-
#!/usr/bin/env python3

# Authors:
# Julio Costella Vicenzi
# Yuri Alves

# netscan agent that implements the NETSCAN_MIB using netscan aplication

import sys, os, signal
from time import sleep
import optparse
import threading

# import local library 
sys.path.insert(1, os.getcwd()+"/../netsnmpagent")
sys.path.insert(1, os.getcwd()+"/../netscan")
import netsnmpagent
import netscan as ns



# Class encapulates the SNMP agent and the NetworkScanner class
class NetscanMIBagent:
    def __init__(self, options, network_addr=None, scan_period=60):
        # create NetworkScanner
        self.netscanner = ns.NetworkScanner(network_addr)
        # A thread to run netscan periodically async
        self.netscan_thread = threading.Thread(None, self.scanner_thread)

        # create SNMP sagent
        self.agent = self.create_agent(options)

        # device table is the main MIB object with a complex initialization
        self.device_table = self.create_table(self.agent, "deviceTable", "onlineDevices")

        # history table 
        self.history_talbe = self.create_table(self.agent, "historyTable", "totalDevices")

        # get network IP addr and mask as separete variables
        (network_ip, mask_number) = str(self.netscanner.network_addr).split("/")

        # create other MIB objects
        self.network_addr = self.agent.IpAddress(
            oidstr  = "NETSCAN-MIB::nsNetworkIP",
            initval = str(network_ip)
        )
        
        self.network_mask = self.agent.Unsigned32(
            oidstr  =   "NETSCAN-MIB::nsNetworkMask",
            initval =   int(mask_number)
        )
        self.scan_period = self.agent.Unsigned32(
            oidstr  =   "NETSCAN-MIB::nsScanPeriod",
            initval =   60
        )

        # this variable is responsible to run netscanner indenfinetly
        # it is set to false to terminate netscanner thread
        self.loop = True
       
    def create_agent(self, options):
        # First, create an instance of the netsnmpAgent class. We specify the
        # fully-qualified path to NETSCAN-MIB.my ourselves here, so that you
        # don't have to copy the MIB to /usr/share/snmp/mibs.
        try:
            agent = netsnmpagent.netsnmpAgent(
                AgentName      = "NetscanAgent",
                MasterSocket   = options.mastersocket,
                PersistenceDir = options.persistencedir,
                MIBFiles       = [ os.path.abspath(os.path.dirname(sys.argv[0])) +
                                "/NETSCAN-MIB.my" ]
            )
        except netsnmpagent.netsnmpAgentException as e:
            print("NetscanMIBagent: {0}".format(e))
            sys.exit(1)
        return agent

    # returns a device_table object used to update table entries
    def create_table(self, agent, table_name, index_name):
        return agent.Table(
            oidstr  = "NETSCAN-MIB::" + table_name,
            indexes = [ agent.OctetString() ],
            columns = [
                (2, agent.IpAddress()),
                (3, agent.Unsigned32()),
                (4, agent.OctetString()),
                (5, agent.OctetString())
            ],
            counterobj = agent.Unsigned32(
                oidstr = "NETSCAN-MIB::" + index_name
            )
        )

    # clears device table and creates new entries based on
    # currently scanned devices
    def update_table(self, table, device_list):
        # clear all rows in table
        table.clear()

        # add new entries
        for device in device_list:
            self.add_device_table_row(table, device)


    # adds a row entry in the device_table
    def add_device_table_row(self, table, network_device : ns.NetworkDevice):
        new_row = table.addRow( [
                self.agent.OctetString(network_device.mac)
                ]
            )
        new_row.setRowCell(2, self.agent.IpAddress(str(network_device.ip)))
        new_row.setRowCell(3, self.agent.Unsigned32(1 if network_device.UP else 0))
        new_row.setRowCell(4, self.agent.OctetString(network_device.vendor[:1024]))
        new_row.setRowCell(5, self.agent.OctetString(
                network_device.first_scan_date.strftime("%d/%m/%Y %H:%M:%S")
            )
        )
    

    # runs the agent and starts network scanner thread
    def start(self):
        try:
            self.agent.start()
        except netsnmpagent.netsnmpAgentException as e:
            print("NetscanMIBagent: {}".format(e))
            sys.exit(1)

        print("NetscanMIBagent: Serving SNMP requests, press ^C to terminate...")
        
        self.netscan_thread.start()
        
        while True:     # process SNMP requests
            self.agent.check_and_process()


    def scanner_thread(self):
        while self.loop:
            try:
                self.netscanner.single_scan()
            except BaseException as e:
                print("Warning! netscanner has stopped with exception: {}".format(e))
                print("Restarting scan...")
                # pensar sobre o que fazer no caso de exceções...
            else:
                # update the MIB with new device information
                if (self.netscanner.new_online_devices_count > 0 or
                    self.netscanner.new_offline_devices_count > 0):
                    self.update_table(self.device_table, self.netscanner.current_scanned_devices)
                    self.update_table(self.history_talbe, self.netscanner.scanned_devices)
            # run loop periodically
            sleep(self.scan_period.value())
        print("Netscanner thread finished!")
    

    # this method ends scanner_thread
    def stop_scanner(self):
        self.loop = False
        # if thread is running, wait for it to finish and join 
        if self.netscan_thread.is_alive():
            self.netscan_thread.join()

    # methods for cleanup when using "with" statements
    def __enter__(self):
        return self

    # shutdown SNMP agent on exit 
    def __exit__(self, exc_type, exc_value, traceback):
        print("Stopping netscan thread...")
        # this finishes the scanner thread if it is running
        self.stop_scanner()

        print("Shutting down NetscanMIBagent...")
        self.agent.shutdown()


def main():
    # Process command line arguments
    parser = optparse.OptionParser()
    parser.add_option(
        "-m",
        "--mastersocket",
        dest="mastersocket",
        help="Sets the transport specification for the master agent's AgentX socket",
        default="/var/run/agentx/master"
    )
    parser.add_option(
        "-p",
        "--persistencedir",
        dest="persistencedir",
        help="Sets the path to the persistence directory",
        default="/var/lib/net-snmp"
    )
    (options, args) = parser.parse_args()

    # use with statement for cleanup on process kill
    with NetscanMIBagent(options) as agent:
        print("Starting netscan MIB agent...")
        agent.start()
#    agent = NetscanMIBagent(options)
    

if __name__ == "__main__":
    main()


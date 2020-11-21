#!/usr/bin/env python3

import os       # cmd line programs
import time     # for sleep()
import ipaddress
import requests
import subprocess
import multiprocessing
from datetime import datetime # for scan date

# netscan scans and logs the current connected network
# and warns of new devices or offline devices

# dependencies: package iproute2 (linux)

# filters a list of string removing whitespace and empty strings
def filter_strings(string_list):
    sl = string_list
    if "" in string_list:
        sl.remove("")

    sl = [ filter_string(s) for s in sl]
    return sl

def filter_string(s):
    s = s.replace(" ", "")  \
        .replace("\n", "")  \
        .replace("\t", "")  \
        .replace("[", "")   \
        .replace("]", "")   \
        .replace("'", "")
    return s

# a single device in the network. Saves info and current time
class NetworkDevice:
    def __init__(self, ip, mac):
        self.ip = ip
        self.mac = mac 
        self.online=True 
        self.set_vendor()
        #self.set_router()
        self.first_scan_date = datetime.now()
        
    # two devices are equal if they share the same mac address
    def is_equal(self, compared_device):
        return self.mac == compared_device.mac
        
    # uses cmd line to check if IP has router flag
    def set_router(self, routers):
        self.router = False
        #self.router = self.ip in routers

    # uses API to check vendor based on mac addr
    def set_vendor(self):
        url = "https://api.macvendors.com/"
        api_key = " \ -H \"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImp0aSI6IjYwNDI4NTNjLWE2ODEtNGJjMC1hYWEwLTQ4NmViNjg4YzY5MyJ9.eyJpc3MiOiJtYWN2ZW5kb3JzIiwiYXVkIjoibWFjdmVuZG9ycyIsImp0aSI6IjYwNDI4NTNjLWE2ODEtNGJjMC1hYWEwLTQ4NmViNjg4YzY5MyIsImlhdCI6MTYwNTg1NDQyMywiZXhwIjoxOTIwMzUwNDIzLCJzdWIiOiI3OTM0IiwidHlwIjoiYWNjZXNzIn0.0QcT4oFqWzDltiFT2TUfindClv4nCANiJoqtoQgf4xJWz1hBMZTqpLeNcpJWo2qmXaMubLkIWtn59-qVMAc98Q\""
        response = requests.get(url+self.mac+api_key)
        if response.status_code != 200: 
            self.vendor = "Unknown"
        else:
            self.vendor = response.content.decode()

    # sets device status and report if it is changed
    def set_status(self, online):
        self.online = online

    # prints current device status as a warning of changed status
    def report_changed_status(self):
        print("Device changed to ", "ONLINE" if self.online else "OFFLINE" , " !")
        self.print()

    def print(self):
        print("Device at IP: %s\tMAC: %s" % (self.ip,self.mac))
        print("Status: ", "Online" if self.online else "Offline")
        print("Router" if self.router else "Host")
        print("First scanned at: ", self.first_scan_date.strftime("%d/%m/%Y %H:%M:%S"))


class NetworkScanner:
    # network_addr must include subnet mask in the x.x.x.x/m format
    # when argument is default, ip is used to retrieve the subnet mask
    # scan period defines the time between network scans in (unit of time)
    def __init__(self, network_addr=""):
        if(network_addr==""):
            # head -1 used to ensure only a single ip address is retrieved
           network_addr = filter_string(str(os.popen("ip route | grep \"src $MAINIP\""
                                    "| awk '{print $1}' | head -1").read()))

        self.network_addr = ipaddress.ip_network(network_addr)
        
        self.scanned_devices = [] # list contains history of every device ever scanned
        self.current_scanned_devices = [] # list of current scanned devices

        # network changes from last scan
        self.new_online_devices_count = 0
        self.new_offline_devices_count = 0

    # does a continuos network scan periodically
    # scan_period = number of seconds between each scan
    def periodic_scan(self, scan_period=30):
        # TODO: open JSON file and read already scanned devices
        print("Performing continuos network device scan")
        # continuosly scan 
        while True:
            self.single_scan()
            # TODO: update log with scanned devices
            self.print_scanned_devices()
            time.sleep(scan_period)

    # ------------ network scan methods ------------------
    # scans the network for available devices
    # updates scanned_devices with new devices and their status
    # updates currrent_scanned_devices with the devices found
    def single_scan(self):
        print("[--Scanning--]")

        pinged_ips = self.ping_sweep()
        
        addrs_dict = self.get_macs(pinged_ips)

        self.update_scanned_devices(addrs_dict)



    # pings every possible ip in the network based on
    # self.max_number_of_devices
    # returns IPs that could be pinged
    def ping_sweep(self):

        # ping job used for multiprocessor
        def ping_job(job_q, results_q):
            DEVNULL = open(os.devnull,'w')
            while True:
                ip = job_q.get()
                if ip is None:break
                
                try: 
                    subprocess.check_call(['ping','-c1',ip],stdout=DEVNULL)
                    results_q.put(ip)
                except: pass

        #Create queue for multiprocess
        jobs,results = multiprocessing.Queue(),multiprocessing.Queue()

        # Create the process to execute ping_sweep
        pool = [multiprocessing.Process(target=ping_job, args=(jobs,results)) 
                        for _ in self.network_addr.hosts()]
    
        # Start the process
        for p in pool: p.start()
        # Start ping in host
        for ip in self.network_addr.hosts(): 
            jobs.put(str(ip))

        for p in pool: jobs.put(None)

        # Join all
        for p in pool: p.join()

        # convert queue to list for easier use later
        pinged_ips = []
        while not results.empty():
            pinged_ips.append(results.get())

        return pinged_ips

    # call arp on ip and return the corresponding mac address
    def get_mac_by_arp(self, ip):
        # get only the first device, since multiple interfaces might be connected
        # to the same device.
        mac = filter_string(str(os.popen("arp -n "+ip+" | awk \'{print $3}\' "
                                            "| tail -n +2 | head -1").read()))
        return mac
    
    # local mac adddr cannot be resolved via arp
    def get_local_mac(self, ip):
        # get the interface associated with the ip
        grep_ip = ip + "/" # this is necessary for grep
        ip_interface = filter_string(str(os.popen("ip addr show" 
                                        "| grep "+grep_ip+" | awk \'{print $NF}\'").read()))
        # get interface mac
        mac = filter_string(str(os.popen("ip link show "+ip_interface+""
                                        "| awk \'{print $2}\' | tail -n 2").read()))
        return mac

    # returns a dictionary with mac as keys and ip as items
    def get_macs(self, pinged_ips):
        addrs_dict = {}
        # local ips mac addr cannot be resolved via arp
        local_ips = self.get_local_ips()
        
        for ip in pinged_ips:
            if ip in local_ips:
                mac = self.get_local_mac(ip)
            else: 
                mac = self.get_mac_by_arp(ip)
            # add ip mac pair
            addrs_dict[mac] = ip
        
        return addrs_dict

    def update_scanned_devices(self, addr_dict):
        self.new_offline_devices_count = 0
        self.new_online_devices_count = 0

        # start by checking if any of the devices went offline
        self.remove_offline_devices(addr_dict)

        # pinged_ips should now only contain devices
        # that were not online. We first check 
        # if they are in scanned_devices 
        # if not, they are added to both current_scanned_devices
        # and scanned_devices
        self.add_devices(addr_dict)

    # Checks addr_dict and compares with current scanned devices
    # removes devices from list if their mac is not in the addr_dict
    # removes ips from pinged list if they are found in the current scanned devices
    def remove_offline_devices(self, addr_dict):
        for dev in self.current_scanned_devices:
            if dev.mac in addr_dict.keys():
                # device is still online, check if ip is not changed
                dict_ip = addr_dict[dev.mac]
                if dict_ip != dev.ip:
                    print("IP on device changed from "+dev.ip+" to "+dict_ip+" !")
                    dev.ip = dict_ip
                    dev.print()
                # delete mac ip pair, since they already exist and are still online
                del addr_dict[dev.mac]
            else:
                # device is now offline
                self.new_offline_devices_count += 1
                dev.set_status(False)
                dev.report_changed_status()
                self.current_scanned_devices.remove(dev)

    # check self.scanned_devices for ips in pinged_ips
    # to see if any of the offline devices went online
    def add_devices(self, addr_dict):
        for dev in self.scanned_devices:
            if dev.mac in addr_dict.keys():
                # mac already exists in past scanned devices,
                # set it as online

                # TODO: refatorar código repetido
                dict_ip = addr_dict[dev.mac]
                if dict_ip != dev.ip:
                    print("IP on device changed from "+dev.ip+" to "+dict_ip+" !")
                    dev.ip = dict_ip
               
                dev.set_status(True)
                dev.report_changed_status()
                del addr_dict[dev.mac]

        # the remaning devices must be new
        for mac, ip in addr_dict.items():
            self.add_new_device(ip, mac)

    # creates NetworkDevice object from ip
    def add_new_device(self, ip, mac):
        self.new_online_devices_count += 1
        dev = NetworkDevice(ip, mac)
        self.scanned_devices.append(dev)
        self.current_scanned_devices.append(dev)
        print("New Device: ")
        dev.print()

    # this must be called every time 
    # since one of the machine's interfaces might go offline
    def get_local_ips(self):
        local_ips = os.popen('hostname -I').read()
        local_ips = local_ips.split(" ")
        local_ips = filter_strings(local_ips)
        return local_ips

    # ---------- Utility methods --------------
    def print_scanned_devices(self):
        print("List devices from last scan:")
        for dev in self.current_scanned_devices:
            dev.print()
            print("-"*30)

    def print_device_history(self):
        print("List of every scanned device in the network")
        for dev in self.scanned_devices:
            dev.print()
            print("-"*30)

def main():
    ns = NetworkScanner()
    print(ns.ping_sweep())
    mac = ns.get_mac_by_arp("192.168.0.1")
    print(mac)

if __name__ == "__main__":
    main()
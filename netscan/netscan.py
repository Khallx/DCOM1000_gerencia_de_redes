# -*- coding: utf-8 -*-
#!/usr/bin/env python3

# Authors:
# Julio Costella Vicenzi
# Yuri Alves
# Lucas Pittella

import os       # cmd line programs
import time     # for sleep()
import ipaddress
import requests
import subprocess
import multiprocessing
from datetime import datetime # for scan date
import argparse
from jhistoric import * 

# netscan scans and logs the current connected network
# and warns of new devices or offline devices

# dependencies: 
# package iproute2 (linux) for ip 

# filters a list of string removing whitespace and empty strings
def filter_strings(string_list):
    sl = string_list
    sl = [ filter_string(s) for s in sl ]

    if "" in sl:
        sl.remove("")

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
    def __init__(self, ip, mac, UP=True, vendor=None):
        self.ip = ip
        self.mac = mac 
        self.UP=UP 
        self.vendor = "Not found" if vendor == None else vendor
        self.set_router()
        self.first_scan_date = datetime.now()

    # uses cmd line to check if IP has router flag
    def set_router(self):
        # check if router flag is UG, else consider device as host
        router_flag = filter_string(os.popen("route -n |" 
                        "grep "+str(self.ip)+
                        "| awk '{print $4}' | head -1")
                        .read())
        self.router = (router_flag == "UG") # if flag is UG, device is router

    # uses API to check vendor based on mac addr
    def get_api_vendor(self):
        url = "https://api.macvendors.com/"
        api_key = " \ -H \"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImp0aSI6IjYwNDI4NTNjLWE2ODEtNGJjMC1hYWEwLTQ4NmViNjg4YzY5MyJ9.eyJpc3MiOiJtYWN2ZW5kb3JzIiwiYXVkIjoibWFjdmVuZG9ycyIsImp0aSI6IjYwNDI4NTNjLWE2ODEtNGJjMC1hYWEwLTQ4NmViNjg4YzY5MyIsImlhdCI6MTYwNTg1NDQyMywiZXhwIjoxOTIwMzUwNDIzLCJzdWIiOiI3OTM0IiwidHlwIjoiYWNjZXNzIn0.0QcT4oFqWzDltiFT2TUfindClv4nCANiJoqtoQgf4xJWz1hBMZTqpLeNcpJWo2qmXaMubLkIWtn59-qVMAc98Q\""
        try:
            response = requests.get(url+self.mac+api_key)
        except Exception as e:
            print(e)
        if response.status_code != 200:
            vendor = "Unknown"
        else:
            vendor = response.content.decode()
        return vendor

    # prints current device state as a warning of changed state
    def report_changed_state(self):
        print("Device changed to ", "UP" if self.UP else "DOWN" , " !")
        self.print()

    def print(self):
        print("Device at IP:"+str(self.ip)+"\tMAC:"+self.mac+
            "\tis " + ("Router" if self.router else "Host"))
        print("Vendor: ", self.vendor)
        print("state: ", "UP" if self.UP else "DOWN")
        print("First scanned at: ", self.first_scan_date.strftime("%d/%m/%Y %H:%M:%S"))

        self.dev = {
            "MAC": self.mac,
            "IP": format(self.ip),
            "UP": self.UP,
            "VENDOR": self.vendor,
            "ROUTER": self.router,
            "FSCAN_DATE": format(self.first_scan_date)
            }

        update_historic('discovery_history.json',self.dev)

class NetworkScanner:
    # network_addr must include subnet mask in the x.x.x.x/m format
    # when argument is default, ip is used to retrieve the subnet mask
    # scan period defines the time between network scans in (unit of time)
    def __init__(self, network_addr=None):
        if(network_addr==None):
            # head -1 used to ensure only a single ip address is retrieved
            network_addr = filter_string(os.popen("ip -o -f inet addr show"
                                                "| awk \'/scope global/ {print $4}\' "
                                                "| head -1").read())
        try:
            # get the base network address based on local ip and mask (x.x.x.x/m)
            # strict false makes the constructor calculate the base network ip
            self.network_addr = ipaddress.ip_network(network_addr, strict=False)
        except ValueError:
            print("Invalid network address. Check your internet connection")
            exit()

        # if the discovery history json file, not exists, create
        if not os.path.exists('discovery_history.json'):
            open('discovery_history.json', 'w+').write('[\n\n]')
        
        # TODO: open JSON file and read already scanned devices
        self.scanned_devices = [] # list contains history of every device ever scanned
        self.current_scanned_devices = [] # list of current scanned devices

        # network changes from last scan
        self.new_online_devices_count = 0
        self.new_offline_devices_count = 0

    # does a continuos network scan periodically
    # scan_period = number of seconds between each scan
    def periodic_scan(self, scan_period=30):
        print("Performing periodic network device scan on "+str(self.network_addr)+
            " every "+str(scan_period)+" seconds")
        # continuosly scan 
        while True:
            self.single_scan()
            # TODO: update log with scanned devices
            if self.new_online_devices_count > 0:
                print(str(self.new_online_devices_count)+" devices are now online!")
            if self.new_offline_devices_count > 0:
                print(str(self.new_offline_devices_count)+" devices are now offline!")
            #self.print_scanned_devices()

            print("[--Scan finished--]")
            time.sleep(scan_period)

    # ------------ network scan methods ------------------
    # scans the network for available devices
    # updates scanned_devices with new devices and their state
    # updates currrent_scanned_devices with the devices found
    def single_scan(self):
        print("[--Scanning--]")

        pinged_ips = self.ping_sweep()
        
        addrs_dict = self.get_macs(pinged_ips)

        self.update_scanned_devices(addrs_dict)

        if  not self.current_scanned_devices:
            print("No connected devices found! Check your connection")


    # pings every possible ip in the network based on
    # self.max_number_of_devices
    # returns IPs that could be pinged
    def ping_sweep(self):

        # ping job used for multiprocessor
        def ping_job(job_q, results_q):
            while True:
                ip = job_q.get()
                if ip is None:break
                
                try: 
                    subprocess.check_call(['ping','-c1',ip], 
                                        stdout=subprocess.DEVNULL, 
                                        stderr=subprocess.DEVNULL)
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

        # convert queue to list and convert to ipaddess.ip_address
        pinged_ips = []
        while not results.empty():
            pinged_ips.append(ipaddress.ip_address(results.get()))

        return pinged_ips

    # call arp on ip and return the corresponding mac address
    def get_mac_by_arp(self, ip):
        # get only the first device, since multiple interfaces might be connected
        # to the same device.
        mac = filter_string(str(os.popen("ip neigh show "+str(ip)+" | awk \'{print $5}\' "
                                          "| head -1").read()))
        if mac == "":
            raise ValueError("Could not find MAC addr for IP: "+str(ip)+" via ARP")
        return mac
    
    # local mac adddr cannot be resolved via arp
    def get_local_mac(self, ip):
        # get the interface associated with the ip
        grep_ip = str(ip) + "/" # this is necessary for grep
        ip_interface = filter_string(str(os.popen("ip addr show" 
                                        "| grep "+grep_ip+" | awk \'{print $NF}\'").read()))
        # get interface mac
        mac = filter_string(str(os.popen("ip link show "+ip_interface+""
                                        "| awk \'{print $2}\' | tail -n +2").read()))
        if mac == "":
            raise ValueError("Could not find MAC addr for local IP: "+str(ip) + " via ip link")
        return mac

    # returns a dictionary with mac as keys and ip as items
    # TODO: verify macs could actually be retrieved.
    def get_macs(self, pinged_ips):
        addrs_dict = {}
        # local ips mac addr cannot be resolved via arp
        local_ips = self.get_local_ips()
        
        for ip in pinged_ips:
            mac = self.get_local_mac(ip) if ip in local_ips else self.get_mac_by_arp(ip)
            # add ip mac pair
            addrs_dict[mac] = ip
        
        return addrs_dict

    def update_scanned_devices(self, addr_dict):
        self.new_offline_devices_count = 0
        self.new_online_devices_count = 0

        # start by checking if any of the devices went offline
        self.remove_offline_devices(addr_dict)

        # addr_dic should now only contain devices
        # that were not online. We first check if they are in scanned_devices 
        # if not, they are added to both current_scanned_devices and scanned_devices
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
                    print("IP on device changed from "+str(dev.ip)+" to "+str(dict_ip)+" !")
                    dev.ip = dict_ip
                    dev.print()
                # delete mac ip pair, since they already exist and are still online
                del addr_dict[dev.mac]
            else:
                # device is now offline
                self.new_offline_devices_count += 1
                dev.UP = False
                dev.report_changed_state()
                self.current_scanned_devices.remove(dev)

    # check self.scanned_devices for ips in pinged_ips
    # to see if any of the offline devices went online
    def add_devices(self, addr_dict):
        for dev in self.scanned_devices:
            if dev.mac in addr_dict.keys():
                # mac already exists in past scanned devices

                # TODO: refatorar código repetido
                dict_ip = addr_dict[dev.mac]
                if dict_ip != dev.ip:
                    print("IP on device changed from "+str(dev.ip)+" to "+str(dict_ip)+" !")
                    dev.ip = dict_ip
               
                dev.UP = True
                dev.report_changed_state()
                # add device to current scanned devices
                self.current_scanned_devices.append(dev)
                del addr_dict[dev.mac]

        # the remaning devices must be new
        for mac, ip in addr_dict.items():
            self.add_new_device(ip, mac)

    # creates NetworkDevice object from ip and append to lists
    def add_new_device(self, ip, mac):
        self.new_online_devices_count += 1
        # checks if mac is in vendor_dict, else pass None as vendor
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
        local_ips = [ipaddress.ip_address(ip) for ip in local_ips]
        return local_ips

    # ---------- vendor methods ------------
    # this is only used if reading MACs from file. Not currently in use
    def read_vendor_file(self):
        # tab separated file
        with open("MACS.txt") as f:
            lines = f.readlines()
            vendor_dict = {}
            for line in lines:
                mac, vendor = line.split(",", 1)
                vendor_dict[mac] = vendor
        return vendor_dict
    

    # get the first 6 bytes of mac address 
    def get_mac_vendor_bytes(self, mac):
        mac = mac.replace("-", "")  \
            .replace(":", "")   \
            .replace(".", "")
        return mac[:6]
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


def get_args():
    def bigger_than_zero(string):
        value = int(string)
        if value < 1:
            raise argparse.ArgumentTypeError("Period must be an integer bigger than zero")
        return value

    parser = argparse.ArgumentParser(description="A periodic scan script.")
    parser.add_argument("-p", dest="period", 
            help="Determines the time between each scan in seconds",
            default=10,
            type=bigger_than_zero, # check if int is positive
            required=False
            )
    parser.add_argument("-n", dest="net_addr", 
            help="The network ip and subnet mask in the format X.X.X.X/M",
            type=ipaddress.ip_network,
            required=False
            )

    return parser.parse_args()

def main():
    cmd_args = get_args()
    ns = NetworkScanner(cmd_args.net_addr)
    ns.periodic_scan(cmd_args.period)

if __name__ == "__main__":
    main()

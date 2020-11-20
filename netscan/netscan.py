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

    sl = [s.replace(" ", "")
            .replace("\n", "")
            .replace("\t", "") 
            .replace("[", "") 
            .replace("]", "") 
            .replace("'", "") 
                                for s in sl]
    return sl

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
        pass
        #self.vendor = requests.get("https://api.macvendors.com/"+self.mac+
        #" \ -H \"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImp0aSI6IjYwNDI4NTNjLWE2ODEtNGJjMC1hYWEwLTQ4NmViNjg4YzY5MyJ9.eyJpc3MiOiJtYWN2ZW5kb3JzIiwiYXVkIjoibWFjdmVuZG9ycyIsImp0aSI6IjYwNDI4NTNjLWE2ODEtNGJjMC1hYWEwLTQ4NmViNjg4YzY5MyIsImlhdCI6MTYwNTg1NDQyMywiZXhwIjoxOTIwMzUwNDIzLCJzdWIiOiI3OTM0IiwidHlwIjoiYWNjZXNzIn0.0QcT4oFqWzDltiFT2TUfindClv4nCANiJoqtoQgf4xJWz1hBMZTqpLeNcpJWo2qmXaMubLkIWtn59-qVMAc98Q\"").text

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
           network_addr = str(os.popen("ip route | grep \"src $MAINIP\""
                                    "| awk '{print $1}' | head -1").read())

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
        pass
        # set the status of every device in history as unchecked
        # # to make sure their status is updated to online of offline according to scan results
        # self.uncheck_scanned_devices_status()

        # print("[--Scanning--]")

        # # TODO: change to ping sweep
        # self.current_scanned_devices = self.scan_host_devices() + self.scan_network_devices() 

        # # check if the scanned devices are stored in history
        # print("[--Scan Finished--]")
        # print("[--Checking new devices--]")
        # self.update_scanned_list()
        # print("[--Checking offline devices--]")
        # # check if any of the devices went offline
        # self.check_offline_devices()


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
                    #subprocess.check_call(['ping','-c1',ip],stdout=DEVNULL)
                    subprocess.check_call(['ping','-c1',ip])
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


    def update_scanned_devices(self, pinged_ips):
        self.new_offline_devices_count = 0
        self.new_online_devices_count = 0

        # start by checking if any of the devices went offline
        self.remove_offline_devices(pinged_ips)

        # pinged_ips should now only contain devices
        # that were not online. We first check 
        # if they are in scanned_devices 
        # if not, they are added to both current_scanned_devices
        # and scanned_devices
        self.add_devices(pinged_ips)


    # rechecks pinged ips and compares with current scanned devices
    # removes devices from list if they are not found in the pinged ips
    # removes ips from pinged list if they are found in the current scanned devices
    def remove_offline_devices(self, pinged_ips):
        for dev in self.current_scanned_devices:
            matching_ip = next((ip for ip in pinged_ips if ip == dev.ip), None)
            if matching_ip == None:
                # device is now offline
                self.new_offline_devices_count += 1
                dev.set_status(False)
                dev.report_changed_status()
                self.current_scanned_devices.remove(dev)
            else:
                # device is still online, remove ip from list
                pinged_ips.remove(matching_ip)

    
    # check self.scanned_devices for ips in pinged_ips
    # to see if any of the offline devices went online
    def add_devices(self, pinged_ips):
        for dev in self.scanned_devices:
            matching_ip = next((ip for ip in pinged_ips if ip == dev.ip), None)
            if matching_ip != None:
                # ip já estava na lsita de devices
                dev.set_status(True)
                dev.report_changed_status()
            else:
                # ip de dispositivo novo
                self.add_new_device(matching_ip)

    # creates NetworkDevice object from ip
    def add_new_device(self, ip):
        # isso não deveria acontecer na real
        if self.is_local_ip(ip):
            pass
        else:
            # essa chamada por ip é redundante
            # mas pode ser usada pra checar se o ip do arp é o mesmo usado como argumento
            arp_ip = filter_strings(str(os.popen('arp -n '+ip+' | awk \'{print $1}\' | tail -n +2').read()))
            arp_mac = filter_strings(str(os.popen('arp -n '+ip+' | awk \'{print $3}\' | tail -n +2').read()))
            dev = NetworkDevice(arp_ip, arp_mac)
            self.scanned_devices.append(dev)
            self.current_scanned_devices.append(dev)

    def is_local_ip(self, ip):
        return ip in self.get_local_ips()

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
    network = ipaddress.ip_network("192.168.0.0/24")
    for x in network.hosts():
        print(x)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3

import os       
import time     
import requests
import subprocess
import multiprocessing
from datetime import datetime 

# netscan scans and logs the current connected network
# and warns of new devices or offline devices

# dependencies: package iproute2 (linux)

# filters a list of string removing whitespace and empty strings
def filter_list(string_list): 
    sl = string_list
    sl = [s.replace(" ", "")
            .replace("\n", "")
            .replace("\t", "") 
            .replace("[", "") 
            .replace("]", "") 
            .replace("'", "") 
                                for s in sl]

    str1 = ""  
    for s in sl: str1 += s   
    
    return str1

# filters a string removing whitespace and empty strings
def filter_strings(string_strings):
    sl = string_strings 
    sl.remove("")
    sl = [s.replace(" ", "")
            .replace("\n", "")
            .replace("\t", "") 
                                for s in sl]
    return sl

def ping_sweep(job_q, results_q):
    DEVNULL = open(os.devnull,'w')
    while True:
        ip = job_q.get()
        if ip is None:break
        
        try: 
            subprocess.check_call(['ping','-c1',ip],stdout=DEVNULL)
            results_q.put(ip)
        except: pass

# a single device in the network. Saves info and current time
class NetworkDevice:
    def __init__(self, ip, mac, online=True):
        self.ip = ip
        self.mac = mac 
        self.vendor = ""
        self.router = False
        self.online = True # True if status has been updated since last scan used to determine if a device went offline
        self.checked_status = True 
        self.first_scan_date = datetime.now()
        self.status_changed = False # set to true if device went from online to offline by set_status

    # two devices are equal if they share the same mac address
    def is_equal(self, compared_device):
        return self.mac == compared_device.mac
        
    # check if IP has in the router list
    def set_router(self, router):
        if(self.ip in router):
            self.router = True

    # uses API to check vendor based on mac addr
    def set_vendor(self): # LIMITED - 1000 requests/day
        self.vendor = requests.get("https://api.macvendors.com/"+self.mac+
        " \ -H \"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzUxMiIsImp0aSI6IjYwNDI4NTNjLWE2ODEtNGJjMC1hYWEwLTQ4NmViNjg4YzY5MyJ9.eyJpc3MiOiJtYWN2ZW5kb3JzIiwiYXVkIjoibWFjdmVuZG9ycyIsImp0aSI6IjYwNDI4NTNjLWE2ODEtNGJjMC1hYWEwLTQ4NmViNjg4YzY5MyIsImlhdCI6MTYwNTg1NDQyMywiZXhwIjoxOTIwMzUwNDIzLCJzdWIiOiI3OTM0IiwidHlwIjoiYWNjZXNzIn0.0QcT4oFqWzDltiFT2TUfindClv4nCANiJoqtoQgf4xJWz1hBMZTqpLeNcpJWo2qmXaMubLkIWtn59-qVMAc98Q\"").text
        
    # checks if status changed
    def check_status_change(self, online):
        return online != self.online

    # sets device status and report if it is changed
    def set_status(self, online):
        if self.check_status_change(online):
            self.report_changed_status()
            self.online = online

    # set status that indicates if device has been checked and updated its status
    def set_checked_status(self, checked):
        self.checked_status = checked

    # chceks if a device is contained in a list 
    # returns the device from the list or None
    def get_equal_device_from_list(self, dev_list):
        for old_dev in dev_list:
            if(self.is_equal(old_dev)):
                return old_dev
        return None

    # prints current device status as a warning of changed status
    def report_changed_status(self):
        print("Device changed to", "ONLINE" if self.online else "OFFLINE" , "!")
        self.print()
    
    def print(self):
        print("Device at IP: %s\tMAC: %s" % (self.ip,self.mac))
        print("Status:", "Online" if self.online else "Offline")
        print("This device is:","Router" if self.router else "Host")
        print("Vendor: %s"% (self.vendor))
        print("First scanned at: ", self.first_scan_date.strftime("%d/%m/%Y %H:%M:%S"))

class NetworkScanner:
    # subnet_addr must include subnet mask in the x.x.x.x/m format
    # when argument is default, ip is used to retrieve the subnet mask
    # scan period defines the time between network scans in (unit of time)
    def __init__(self, subnet_addr=""):
        if(subnet_addr==""):
            #Get mask of network
            mask = os.popen('ip -o -f inet addr show | awk \'/scope global/ {print $4}\' | head -1 | grep -o \'/.*\' | cut -c 2-').read()
            # Calculate poll of ips
            self.subnet_addr = (2 **(32 - int(mask))-1) # 2^(32-24)-1 = 255 
        else:
            self.subnet_addr = subnet_addr

        self.scanned_devices = [] # list contains history of every device ever scanned
        self.current_scanned_devices = [] # list of current scanned devices

    # does a continuos network scan periodically
    # scan_period = number of seconds between each scan
    def periodic_scan(self, scan_period=30):
        # TODO: open JSON file and read already scanned devices
        print("Performing continuos network device scan")
        # continuosly scan 
        while True:
            self.single_scan()
            # TODO: update log with scanned devices
            #self.print_scanned_devices()
            print(self.current_scanned_devices)
            time.sleep(scan_period)

    # ------------ network scan methods ------------------
    # scans the network for available devices
    # updates scanned_devices with new devices and their status
    # updates currrent_scanned_devices with the devices found
    def single_scan(self):
        # set the status of every device in history as unchecked
        # to make sure their status is updated to online of offline according to scan results
        #self.uncheck_scanned_devices_status()

        print("[--Scanning--]")

        # Create queue for multiprocess
        self.jobs,self.results = multiprocessing.Queue(),multiprocessing.Queue()

        # Create the process to execute ping_sweep
        self.pool = [multiprocessing.Process(target=ping_sweep, args=(self.jobs,self.results)) for i in range(self.subnet_addr)]
    
        # Start the process
        for p in self.pool: p.start()
        # Start ping in host
        for i in range(1,self.subnet_addr): self.jobs.put('192.168.1.{0}'.format(i))
        for p in self.pool: self.jobs.put(None)

        # Join all
        for p in self.pool: p.join()
        
        # TMP list to IP
        self.current_scanned_devices = []

        # While have valid IP, iterate
        while not self.results.empty():
            # Get the ip of current iterate
            self.cur_ip = self.results.get()

            # Verify if discovered IP, not is the local IP
            if (self.cur_ip not in local_ip):
                self.tmp_arp_ip = filter_list(str(os.popen('arp -n '+self.cur_ip+' | awk \'{print $1}\' | tail -n +2').read()))
                self.tmp_arp_mac = filter_list(str(os.popen('arp -n '+self.cur_ip+' | awk \'{print $3}\' | tail -n +2').read()))

                self.current_scanned_devices.append([self.tmp_arp_ip,self.tmp_arp_mac])

        #print(self.current_scanned_devices)
        
            #check if the scanned devices are stored in history
        #print("[--Scan Finished--]")
        #print("[--Checking new devices--]")
            #self.update_scanned_list()
        #print("[--Checking offline devices--]")
        # check if any of the devices went offline
            #self.check_offline_devices()

    # ------------ REVIEW ------------ #
    # Olhar as linhas abaixo do if (cur_ip not in local_ip):, creio que pode 
    # ajudar para o metodo get_host_ip_mac, pois o cmd_out me retornou somente 
    # o MAC e não IP E MAC
    # ------------ REVIEW ------------ #

    # calls ip addr show and returns matching (ip_list, mac_list)
    def get_host_ip_mac(self):        
        # The first line should contain an MAC addr followed by a line containing a IP addr
        # first grep: filter for link and inet lines that contain mac and ip
        # second grep: discard lines with loopback addr and ipv6 addr
        # awk: read only ip and mac addr
        cmd_out = str(os.popen("ip addr show | grep -e \"link/\" -e \"inet\""
                            "| grep -v -e \"host lo\" -e \"link/loopback\" -e \"inet6\""
                            "| awk '{print $2}'").read()) 
        
        # split each line into a list
        cmd_list = cmd_out.splitlines()
        if "" in cmd_list:
            cmd_list.remove("")

        if len(cmd_list) % 2 != 0:
            raise ValueError(str(cmd_list))

        # each odd line contains an ip, even line a mac
        # returns ip_list, mac_list
        return cmd_list[1::2], cmd_list[::2]
    
    # ------------ REVIEW ------------ #
    # Creio que o single scan já contemple isso
    # Talvez seja interessante modularmos só a busca
    # dos hosts
    # ------------ REVIEW ------------ #

    # returns list containing NetworkDevices found in host
    # def scan_host_devices(self):
    #     ip_list, mac_list = self.get_host_ip_mac()

    #     host_devices = []
    #     for ip, mac in zip(ip_list, mac_list):
    #         ip = ip.split("/")[0] # remove subnet mask from addr
    #         host_devices.append(NetworkDevice(ip, mac))
        
    #     return host_devices


    # arp scan the network for devices other than the host's
    # returns ip_list, mac_list with matching values
    def get_network_ip_mac(self):
        # arp: return all network addr (excluding host's)
        # awk: filter to display ip and mac each line
        # tail: remove arp header
        cmd_out = str(os.popen("arp | awk '{print $1 \" \" $3}' | tail -n +2").read())

        cmd_list = cmd_out.splitlines()
        # remove duplicate lines
        cmd_list = list(set(cmd_list))
        # split ip and mac 
        cmd_list = [line.split(" ") for line in cmd_list]

        # return ip_list, mac_list
        return map(list, zip(*cmd_list))


    # returns a list of network devices found by the arp cmd call (does not show host devices)
    def scan_network_devices(self):
        ip_list, mac_list = self.get_network_ip_mac()            

        net_devices = [NetworkDevice(ip, mac) for ip,mac in zip(ip_list,mac_list)]
        return net_devices

        # ------------ REVIEW ------------ #
    # ESSES MÉTODOS NÃO REVISEI NADA   #
    # ------------ REVIEW ------------ #

    # ------------ network change methods ------------------

    # updates the scanned_devices list based on found devices
    # as well as updating their status
    # reports if devices changed status
    def update_scanned_list(self):
        # check if device has already been scanned previously.
        for i, new_dev in enumerate(self.current_scanned_devices):
            # new devices are added to list
            equal_dev = new_dev.get_equal_device_from_list(self.scanned_devices)
            if equal_dev == None:
                # add new device to scanned devices
                self.add_new_device(new_dev)
                # update list with the new information
                self.current_scanned_devices[i] = new_dev
            else:
                equal_dev.set_status(True)
                # indicate that the status has been updated
                equal_dev.set_checked_status(True)

                # copy old device information to current scan list
                self.current_scanned_devices[i] = equal_dev
    
    def check_offline_devices(self):
        for dev in self.scanned_devices:
            # indicates the device was not in the scanned list and must have gone offline
            if not dev.checked_status and dev.online:                    
                dev.set_status(False)
        
    def uncheck_scanned_devices_status(self):
        for dev in self.scanned_devices:
            dev.set_checked_status(False)

    def add_new_device(self, dev):
        # this is done here to avoid too many cmd line and API calls
        dev.set_router()
        dev.set_vendor()
        self.scanned_devices.append(dev)
        # report new device
        print("New device found!")
        dev.print()

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

    # ------------ REVIEW ------------ #
    # ESSES MÉTODOS NÃO REVISEI NADA   #
    # ------------ REVIEW ------------ #

if __name__ == '__main__':
    
    # ------------ REVIEW ------------ #
    # ESSES LINHAS SÃO RESPONSAVEIS    #
    # POR POPULAR LISTAS DE IPS E MACS #
    # LOCAIS WIFI E CABO               #
    # ------------ REVIEW ------------ #

    # create a list with ip's of machine 
    get_ip = os.popen('hostname -I').read()
    local_ip = get_ip[:-2].split(" ")

    # create a list with mac's of machine
    get_mac = str(os.popen('ip addr | grep ether | awk {\'print $2\'}').read())
    local_mac = get_mac[:-1].split("\n")  

    # ------------ REVIEW ------------ #
    # ESSES LINHAS SÃO RESPONSAVEIS    #
    # POR POPULAR LISTAS DE IPS E MACS #
    # LOCAIS WIFI E CABO               #
    # ------------ REVIEW ------------ #

    ns = NetworkScanner()
    ns.periodic_scan(1)
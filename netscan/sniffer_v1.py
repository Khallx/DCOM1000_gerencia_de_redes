#!/usr/bin/env python3
# ------------------------------------------------------------------------------------------------------------------
# Autor        Yuri Oliveira Alves <yuri.alves@ecomp.ufsm.br>
# Criado Em    20/11/2020
# ------------------------------------------------------------------------------------------------------------------

import os       
import time     
import requests
import subprocess
import multiprocessing
from datetime import datetime 

def filter_list(string_list): # review this func
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

def filter_strings(string_strings):
    sl = string_strings # ?? KKK
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
    def set_vendor(self):
        # Review api token 
        # only 1000 requests/day
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


if __name__ == '__main__':
    
    # create a list with ip's of machine
    get_ip = os.popen('hostname -I').read()
    local_ip = get_ip[:-2].split(" ")

    # create a list with mac's of machine
    get_mac = str(os.popen('ip addr | grep ether | awk {\'print $2\'}').read())
    local_mac = get_mac[:-1].split("\n")
    
    # create a list with router UG
    get_router = os.popen('route -n | grep \'UG[ \t]\' | awk \'{print $2}\'').read()
    router = get_router[:-1].split(" ")

    # Calculate poll of ips
    mask = os.popen('ip -o -f inet addr show | awk \'/scope global/ {print $4}\' | head -1 | grep -o \'/.*\' | cut -c 2-').read()
    ip_pool = (2 **(32 - int(mask))-1) #255
    
    # Create queue for multiprocess
    jobs,results = multiprocessing.Queue(),multiprocessing.Queue()

    # Create the process to execute ping_sweep
    pool = [multiprocessing.Process(target=ping_sweep, args=(jobs,results)) for i in range(ip_pool)]
 
    # Start the process
    for p in pool: p.start()
    # Start ping in host
    for i in range(1,ip_pool): jobs.put('192.168.1.{0}'.format(i))
    for p in pool: jobs.put(None)

    # Join result
    for p in pool: p.join()

    tmp_discover = []

    # While have valid IP, iterate
    while not results.empty():
        # get the ip of current iterate
        cur_ip = results.get()

        # append to tmp list with discovered ip's
        #tmp_discover.append(cur_ip)
        
        # verify if IP not in local 
        # local IP don't have a arp line table
        if (cur_ip not in local_ip):
            tmp_arp_ip = filter_list(str(os.popen('arp -n '+cur_ip+' | awk \'{print $1}\' | tail -n +2').read()))
            tmp_arp_mac = filter_list(str(os.popen('arp -n '+cur_ip+' | awk \'{print $3}\' | tail -n +2').read()))
       
        tmp_discover.append([tmp_arp_ip,tmp_arp_mac])


    print(tmp_discover)

    #np = NetworkDevice('192.168.1.1','e4:34:93:79:14:cf')

# ------------------------------------------------------------------------------------------------------------------
# FIM SCRIPT.
# ------------------------------------------------------------------------------------------------------------------

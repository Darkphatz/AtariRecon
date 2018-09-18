#!/usr/bin/env python
import subprocess
import multiprocessing
from multiprocessing import Process, Queue
import os
from os import path
import time
import fileinput
import atexit
import sys
sys.dont_write_bytecode = True
from nmapmenu import npoptions
from webmenu import woptions
from searchmenu import soptions
import socket
import commands


start = time.time()

class bcolors:
    HEADER = '\033[94m'
    OKCAUTION = '\033[95m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

print bcolors.HEADER
print "############################################################"
print "!!!!                                                   !!!!!"
print "!!!!                ##          ##                     !!!!!"
print "!!!!                  ##      ##                       !!!!!"
print "!!!!                 ##############                    !!!!!"
print "!!!!               ####  ######  ####                  !!!!!"
print "!!!!             ######################                !!!!!"
print "!!!!             ##  ##############  ##                !!!!!"
print "!!!!             ##  ##          ##  ##                !!!!!"
print "!!!!                   ####  ####                      !!!!!"
print "!!!! 						       !!!!!"
print "!!!!                   Atari 2049                      !!!!!"
print "############################################################"

print " "

# checks location path, if not available mkdir
def checkpath(location):
    try: 
        os.makedirs(location)
    except OSError:
        if not os.path.isdir(location):
           raise

def make_dir(scanip, location):
        print ""
	print bcolors.WARNING + "[+] Getting things ready now..." + bcolors.ENDC
	subprocess.check_output("mkdir" + " " + location + scanip, shell=True)
	subprocess.check_output("mkdir" + " " + location + scanip + "/Exploits/", shell=True)
	subprocess.check_output("mkdir" + " " + location + scanip + "/Privesc/", shell=True)
	subprocess.check_output("mkdir" + " " + location + scanip + "/Report/", shell=True)
	print bcolors.WARNING + "[+] Pen-template sent to " + location + scanip + "/Report/"+ bcolors.ENDC
	subprocess.check_output("cp template.md "+ location + scanip + "/Report"+ "/template.md", shell=True)
	subprocess.check_output("sed -i -e 's/INSERTIPADDRESS/" + scanip + "/g' " + location + scanip + "/Report" + "/template.md", shell=True)
        print bcolors.OKGREEN + "[+] Completed setting up folders in: " + location + scanip + "/" + bcolors.ENDC


# multi process function 
def multProc(targetin, scanip, port):
    jobs = []
    p = multiprocessing.Process(target=targetin, args=(scanip,port))
    jobs.append(p)
    p.start()
    return

# Write to template function
def write_to_file(ip_address, enum_type, data):
    file_path_temp = '%s%s/Report/template.md' % (location, scanip)
    paths = [file_path_temp]
    print bcolors.OKGREEN + "[+] Writing " + enum_type + " to template file:\n " + file_path_temp + bcolors.ENDC

    for path in paths:
	if enum_type == "opt1":
	    subprocess.check_output("replace INSERTNMAPAUTO \"" + data + "\"  -- " + path, shell=True)
	if enum_type == "opt2":
	    subprocess.check_output("replace INSERTSMBAUTO \"" + data + "\"  -- " + path, shell=True)
    return


if __name__=='__main__':
    # Select target ip address
    host_name = socket.gethostname()
    host_ip = os.popen('ip addr show eth0').read().split("inet ")[1].split("/")[0]
    print ("Hostname: " + host_name)
    print ("Host IP: " + host_ip)
    command = "nmap -n -sP %s/24" % (host_ip)
    results = subprocess.check_output(command, shell=True)
    print results
    ip_address = raw_input("Please enter target ip address: ")
    scanip = ip_address.rstrip()
    location = raw_input(("Enter output folder location:     " + chr(8)*4))
    checkpath(location)
    dirs = os.listdir(location)

    if scanip in dirs:
	print "Files already created"
    elif scanip not in dirs:
	make_dir(scanip, location)


def menu():
    #Options printed to use function
    print bcolors.HEADER
    print "################   Main Menu   #############################"
    print ""
    print "1) Nmap Menu"
    print "2) DNS/Web Menu"
    print "3) Searchsploit Query"
    print "4) Scan everything automatically"
    print "5) Quit script"
    print ""
    print "############################################################"

    print bcolors.ENDC
    return choice

# Manual Functions
def opt1(): # Nmap Menu
    os.system('clear')
    npoptions(scanip, location)

def opt2(): # Web scanning
    os.system('clear')
    woptions(scanip, location)

def opt3(): # Searchsploit Query
    os.system('clear')
    soptions(scanip, location)


## Automatic Check
def enum4(scanip, port):
    print bcolors.HEADER + "[+] Detected SMB on " + scanip + ":" + port + bcolors.ENDC
    print bcolors.HEADER + "[+] Performing enum4linux smb scan for " + scanip + ":" + port + bcolors.ENDC
    enum4linux = "enum4linux -a %s" % (scanip)
    enum4linux_results = subprocess.check_output(enum4linux, shell=True)
    print bcolors.OKGREEN + "[+] CHECK FILE - Finished with ENUM4LINUX-Nmap-scan for " + scanip + bcolors.ENDC
    write_to_file(scanip, "opt2", enum4linux_results)
    return

def nmapsmb(scanip, port):
    print bcolors.OKGREEN + "[+] Detected SMB on " + scanip + ":" + port + bcolors.ENDC
    print bcolors.OKGREEN + "[+] Performing nmap smb scan for " + scanip + ":" + port + bcolors.ENDC
    nmapsmb = "nmap -p 139,445 --script=smb-vuln* " + scanip + bcolors.ENDC
    nmapsmb_results = subprocess.check_output(nmapsmb, shell=True)
    write_to_file(scanip, "opt2", nmapsmb_results)
    return 

## Start Scan
def nmapScan():
   print "INFO: Running general TCP nmap scans for " + scanip
   TCPSCAN = "nmap -F -A -sS -v3 %s -oN '%s%s.nmap' -oX '%s%s_nmap_scan_import.xml'"  % (scanip, location, scanip, location, scanip)
   results_TPSCAN = subprocess.check_output(TCPSCAN, shell=True)
   write_to_file(scanip, "opt1", results_TPSCAN)
   return results_TPSCAN
 
def opt4():
   results = nmapScan() ##Initial scan results 
   serv_dict = {}
   lines = results.split("\n") ## Organize results per ports open 
   for line in lines:
        ports = []
        line = line.strip()
        if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
            # print line
            while "  " in line:
                line = line.replace("  ", " ");
                linesplit= line.split(" ")
                service = linesplit[2] # grab the service name

            port = line.split(" ")[0] # grab the port
            # print port
            if service in serv_dict:
                ports = serv_dict[service] # if the service is already in the dict, grab the port list

            ports.append(port)
            print ports
            serv_dict[service] = ports # add service to the dictionary along with the associated port(2)
   for serv in serv_dict: # go through the service dictionary to call additional targeted enumeration functions
        ports = serv_dict[serv]
        #if (serv == "http") or (serv == "http-proxy") or (serv == "http-alt") or (serv == "http?"):
        #    for port in ports:
        #        port = port.split("/")[0]
        #        multProc(httpEnum, scanip, port)
        if (serv == "rpcbind") or (serv == "smb"):
            for port in ports:
                port = port.split("/")[0]
                #enum4(scanip, port)
		nmapsmb(scanip, port)
        #if (serv == "
   return




# Start Program Here 
choice = ''
loop = 1
while loop == 1:
    menu()
    choice = int(raw_input("Please enter option: "))
    print ""
    if choice == 1:
        opt1()
    elif choice == 2:
        opt2()
    elif choice == 3:
        opt3()
    elif choice == 4:
        opt4()
    elif choice == 5: 
        loop = 0
        os.system('clear')
        print ""
	print "Please remember to check %s%s/report/template.md for more information." %(location, scanip)
        print ""
    else:
        print ""
        os.system('clear')
	print bcolors.WARNING + "That's not a valid choice, please try again." + bcolors.ENDC
        print ""
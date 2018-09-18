import subprocess
import sys
import os

class bcolors:
    HEADER = '\033[94m'
    OKCAUTION = '\033[95m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def write_to_file(location, scanip, enum_type, data):

    file_path_temp = '%s%s/Report/template.md' % (location, scanip)
    paths = [file_path_temp]
    print bcolors.OKGREEN + "[+] Writing results to template file:\n" + file_path_temp + bcolors.ENDC

    for path in paths:
	if enum_type == "Option 1":
	    subprocess.check_output("replace HOSTDISCVRY \"" + data + "\"  -- " + path, shell=True)
	if enum_type == "Option 2":
	    subprocess.check_output("replace FASTNMAP \"" + data + "\"  -- " + path, shell=True)
	if enum_type == "Option 3":
	    subprocess.check_output("replace OSDETECTION \"" + data + "\"  -- " + path, shell=True)
	if enum_type == "Option 4":
	    subprocess.check_output("replace RSERVERVERSION \"" + data + "\"  -- " + path, shell=True)
	if enum_type == "Option 5":
	    subprocess.check_output("replace FIREWALLSTATUS \"" + data + "\"  -- " + path, shell=True)
	if enum_type == "Option 6":
	    subprocess.check_output("replace FIREWALLENABLED \"" + data + "\"  -- " + path, shell=True)
	if enum_type == "Option 7":
	    subprocess.check_output("replace TOP20TCP \"" + data + "\" --  " + path, shell=True)
	if enum_type == "Option 8":
	    subprocess.check_output("replace UDPPORTSAVAIL \"" + data + "\"  -- " + path, shell=True)
	if enum_type == "Option 9":
	    subprocess.check_output("replace MACTCPSCAN \"" + data + "\"  -- " + path, shell=True)
	#if enum_type == "Option 10":
        #    try:
	#    	out_bytes = subprocess.check_output("replace VULNSCAN \"" + data + "\"  -- " + path, shell=True)
        #    except subprocess.CalledProcessError as e:
        #    	out_bytes = e.output
        #    	code      = e.returncode
        return

def nmenu(scanip):
    #Options printed to use function
    print bcolors.HEADER
    print "################   NMAP Menu  #############################"
    print ""
    print "1)  Host discovery %s/24" %scanip #nmap -n -sP IPADDRESS/24
    print "2)  Fast Nmap" # nmap -F IPADDRESS -oA root/folder/quick.nmap
    print "3)  OS and version detection" #nmap -A IPADDRESS
    print "4)  Remote server / daemon versions" #nmap -sV IPADDRESS
    print "5)  Check host firewall status" #nmap -sA IPADDRESS
    print "6)  Scan host with firewall enabled" #nmap -PN IPADDRESS
    print "7)  Check most common 20 TCP ports" #nmap --top-ports 20 IPADDRESS
    print "8)  Scan UDP ports" #unicornscan -r300 -mU IPADDRESS
    print "9)  Mac address spoofed TCP scan" #nmap -v -sT -PN --spoof-mac 0 IPADDRESS
    print "10) Check for vulnerabilities" #nmap -Pn --script vuln IPADDRESS
    print "11) Custom shell command" #User inputs their own shell command
    print "12) Go back to main menu"
    print ""
    print "############################################################"
    print bcolors.ENDC
    
def host_disc(scanip, location):
    print bcolors.OKGREEN + ("[+] Performing 'nmap -n -sP %s/24'" % scanip) + bcolors.ENDC
    command = "nmap -n -sP %s/24" % (scanip)
    results = subprocess.check_output(command, shell=True)
    print ""
    show_results = raw_input("Would you like to see results? ")
    print ""
    if show_results == "y":
       print bcolors.OKGREEN + "[+] Scan finished, see results below:"+ bcolors.ENDC
       print results
    elif show_results == "n":
       os.system('clear')
       print "No problem...! "
       print ""
    write_to_file(location, scanip, "Option 1", results)

def fast_nmap(scanip, location):
    print bcolors.OKGREEN + ("[+] Performing 'nmap -F %s'" % scanip) + bcolors.ENDC
    command = "nmap -F %s -oA %s%s/quick.nmap" % (scanip, location, scanip)
    results = subprocess.check_output(command, shell=True)
    print ""
    show_results = raw_input("Would you like to see results? ")
    print ""
    if show_results == "y":
       print bcolors.OKGREEN + "[+] Scan finished, see results below:"+ bcolors.ENDC
       print results
    elif show_results == "n":
       os.system('clear')
       print "No problem...! "
       print ""
    write_to_file(location, scanip, "Option 2", results)

def os_version(scanip, location):
    print bcolors.OKGREEN + ("[+] Performing 'nmap -A %s'" % scanip) + bcolors.ENDC
    command = "nmap -A %s" % (scanip)
    results = subprocess.check_output(command, shell=True)
    print ""
    show_results = raw_input("Would you like to see results? ")
    print ""
    if show_results == "y":
       print bcolors.OKGREEN + "[+] Scan finished, see results below:"+ bcolors.ENDC
       print results
    elif show_results == "n":
       os.system('clear')
       print "No problem...! "
       print ""
    write_to_file(location, scanip, "Option 3", results)

def server_daemon(scanip, location):
    print bcolors.OKGREEN + ("[+] Performing 'nmap -sV %s'" % scanip) + bcolors.ENDC
    command = "nmap -sV %s" % (scanip)
    results = subprocess.check_output(command, shell=True)
    print ""
    show_results = raw_input("Would you like to see results? ")
    print ""
    if show_results == "y":
       print bcolors.OKGREEN + "[+] Scan finished, see results below:"+ bcolors.ENDC
       print results
    elif show_results == "n":
       os.system('clear')
       print "No problem...! "
       print ""
    write_to_file(location, scanip, "Option 4", results)

def host_firewall_status(scanip, location):
    print bcolors.OKGREEN + ("[+] Performing 'nmap -sA %s'" % scanip) + bcolors.ENDC
    command = "nmap -sA %s" % (scanip)
    results = subprocess.check_output(command, shell=True)
    print ""
    show_results = raw_input("Would you like to see results? ")
    print ""
    if show_results == "y":
       print bcolors.OKGREEN + "[+] Scan finished, see results below:"+ bcolors.ENDC
       print results
    elif show_results == "n":
       os.system('clear')
       print "No problem...! "
       print ""
    write_to_file(location, scanip, "Option 5", results)

def firewall_enabled(scanip, location):
    print bcolors.OKGREEN + ("[+] Performing 'nmap -PN %s'" % scanip) + bcolors.ENDC
    command = "nmap -PN %s" % (scanip)
    results = subprocess.check_output(command, shell=True)
    print ""
    show_results = raw_input("Would you like to see results? ")
    print ""
    if show_results == "y":
       print bcolors.OKGREEN + "[+] Scan finished, see results below:"+ bcolors.ENDC
       print results
    elif show_results == "n":
       os.system('clear')
       print "No problem...! "
       print ""
    write_to_file(location, scanip, "Option 6", results)

def TCP_top20(scanip, location):
    print bcolors.OKGREEN + ("[+] Performing 'nmap --top-ports 20 %s'" % scanip) + bcolors.ENDC
    command = "nmap --top-ports 20 %s" % (scanip)
    results = subprocess.check_output(command, shell=True)
    print ""
    show_results = raw_input("Would you like to see results? ")
    print ""
    if show_results == "y":
       print bcolors.OKGREEN + "[+] Scan finished, see results below:"+ bcolors.ENDC
       print results
    elif show_results == "n":
       os.system('clear')
       print "No problem...! "
       print ""
    write_to_file(location, scanip, "Option 7", results)

def udp_scan(scanip, location):
    print bcolors.OKGREEN + ("[+] Performing 'unicornscan -r300 -mU %s'" % scanip) + bcolors.ENDC
    command = "unicornscan -r300 -mU %s" % (scanip)
    results = subprocess.check_output(command, shell=True)
    print ""
    show_results = raw_input("Would you like to see results? ")
    print ""
    if show_results == "y":
       print bcolors.OKGREEN + "[+] Scan finished, see results below:"+ bcolors.ENDC
       print results
    elif show_results == "n":
       os.system('clear')
       print "No problem...! "
       print ""
    write_to_file(location, scanip, "Option 8", results)

def spoof_mac(scanip, location):
    print bcolors.OKGREEN + ("[+] Performing 'nmap -v -sT -Pn --spoof-mac 0 %s'" % scanip) + bcolors.ENDC
    command = "nmap -v -sT -Pn --spoof-mac 0 %s" % (scanip)
    results = subprocess.check_output(command, shell=True)
    print ""
    show_results = raw_input("Would you like to see results? ")
    print ""
    if show_results == "y":
       print bcolors.OKGREEN + "[+] Scan finished, see results below:"+ bcolors.ENDC
       print results
    elif show_results == "n":
       os.system('clear')
       print "No problem...! "
       print ""
    write_to_file(location, scanip, "Option 9", results)

def vuln_scan(scanip, location):
    print bcolors.OKGREEN + ("[+] Performing 'nmap -Pn --script vuln %s'" % scanip) + bcolors.ENDC
    command = "nmap -Pn --script vuln %s" % (scanip)
    results = subprocess.check_output(command, shell=True)
    print ""
    show_results = raw_input("Would you like to see results? ")
    print ""
    if show_results == "y":
       print bcolors.OKGREEN + "[+] Scan finished, see results below:"+ bcolors.ENDC
       print results
    elif show_results == "n":
       os.system('clear')
       print "No problem...! "
       print ""
    #write_to_file(location, scanip, "Option 10", results)
    

def custom_shell(scanip, location):
    ncustom = raw_input("[+] Please type custom command i.e 'nmap -sV %s' : " % (scanip)) 
    print bcolors.OKGREEN + "[+] Executing shell command: "+ bcolors.ENDC
    print bcolors.HEADER + ncustom + bcolors.ENDC
    print ""
    ncust_results = subprocess.check_output(ncustom, shell=True)
    print bcolors.OKGREEN + "[+]See results below for executed command: " + scanip + bcolors.ENDC
    print ncust_results

def npoptions(scanip, location):
   choice = 1
   loop = 1
   while loop == 1:
      nmenu(scanip)
      choice = int(raw_input("Please enter option: "))
      print ""
      if choice == 1:
          host_disc(scanip, location)
      if choice == 2:
          fast_nmap(scanip, location)
      if choice == 3:
          os_version(scanip, location)
      if choice == 4:
          server_daemon(scanip, location)
      if choice == 5:
          host_firewall_status(scanip, location)
      if choice == 6:
          firewall_enabled(scanip, location)
      if choice == 7:
          TCP_top20(scanip, location)
      if choice == 8:
          udp_scan(scanip, location)
      if choice == 9:
          spoof_mac(scanip, location)
      if choice == 10:
          vuln_scan(scanip, location)
      if choice == 11:
          custom_shell(scanip, location)
      elif choice == 12:
          os.system('clear')
          loop = 0
          choice = 0





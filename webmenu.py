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
    print bcolors.OKGREEN + "[+] Writing " + enum_type + " to template file:\n " + file_path_temp + bcolors.ENDC

    for path in paths:
	if enum_type == "Option 1":
	    subprocess.check_output("replace DNSRECON \"" + data + "\"  -- " + path, shell=True)
        if enum_type == "Option 2":
	    subprocess.check_output("replace DNSBRUTE \"" + data + "\"  -- " + path, shell=True)
    

def dmenu(scanip):
    #Options printed to use function
    print bcolors.HEADER
    print "################   DNS/Web Menu  ###########################"
    print ""
    print "1) DNSrecon simple" #dnsrecon -t std -d domain.com
    print "2) DNSrecon bruteforce" #dnsrecon -d domain.com -D /usr/share/wordlists/dnsmap.txt -t brt
    print "3) Dig domain" #dig domain.com
    print "4) Dirb common" #dirb http://domain.com/ or http://IPADDRESS/
    print "5) Dirb vuln scan" #display vuln list and select "/usr/share/dirb/wordlists/vuln"
    print "6) Go back to main menu"
    print ""
    print "############################################################"
    print bcolors.ENDC
    

def dns_recon(scanip, location):
    domain = raw_input("Please enter domain name: ")
    print bcolors.OKGREEN + ("[+] Performing 'dnsrecon -t std -d %s'" % domain) + bcolors.ENDC
    command = "dnsrecon -t std -d %s" % (domain)
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

def dns_brute(scanip, location):
    domain = raw_input("Please enter domain name: ")
    print bcolors.OKGREEN + ("[+] Performing 'dnsrecon -d %s -D /usr/share/wordlists/dnsmap.txt -t brt'" % domain) + bcolors.ENDC
    command = "dnsrecon -d %s -D /usr/share/wordlists/dnsmap.txt -t brt" % (domain)
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


def dig_domain(scanip, location):
    domain = raw_input("Please enter domain name: ")
    print bcolors.OKGREEN + ("[+] Performing 'dig %s'" % domain) + bcolors.ENDC
    command = "dnsrecon -d %s -D /usr/share/wordlists/dnsmap.txt -t brt" % (domain)
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

def dirb_comm(scanip, location):
    domain = raw_input("Please enter http://domain.com or http://IPADDRESS/: ")
    print bcolors.OKGREEN + ("[+] Performing 'dirb %s'" % domain) + bcolors.ENDC
    command = "dirb %s" % (domain)
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

def dirb_vuln(scanip, location):
    domain = raw_input("Please enter http://domain.com or http://IPADDRESS/: ")
    print ""
    vuln_list = "ls /usr/share/dirb/wordlists/vulns/"
    vuln_result = subprocess.check_output(vuln_list, shell=True)
    print vuln_result
    print ""
    vuln = raw_input("Please type the vuln wordlist name .i.e apache.txt: ")
    command = "dirb %s /usr/share/dirb/wordlists/vulns/%s" % (domain, vuln)
    print bcolors.OKGREEN + ("[+] Performing 'dirb %s /usr/share/dirb/wordlists/vulns/%s'" % (domain,vuln)) + bcolors.ENDC
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


def woptions(scanip, location):
   choice = 1
   loop = 1
   while loop == 1:
      dmenu(scanip)
      choice = int(raw_input("Please enter option: "))
      print ""
      if choice == 1:
          dns_recon(scanip, location)
      if choice == 2:
          dns_brute(scanip, location)
      if choice == 3:
          dig_domain(scanip, location)
      if choice == 4:
          dirb_comm(scanip, location)
      if choice == 5:
          dirb_vuln(scanip, location)
      elif choice == 6:
          os.system('clear')
          loop = 0
          choice = 0

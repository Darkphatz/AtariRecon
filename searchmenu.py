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
	if enum_type == "opt1":
	    subprocess.check_output("replace INSERTAVAILHOSTS \"" + data + "\"  -- " + path, shell=True)

def smenu(scanip):
    #Options printed to use function
    print bcolors.HEADER
    print "################   Searchsploit Query  #####################"
    print ""
    print "1) Find exploit" #search for exploit
    print "2) Copy exploit" # copy exploit
    print "3) Open exploit folder" #open natulis folder 
    print "4) Go back to main menu"
    print ""
    print "############################################################"
    print bcolors.ENDC
    

def check_sploit(scanip, location):
    squery = raw_input("Which term would you like to search for? ")
    print ""
    print bcolors.OKGREEN + ("[+] Checking searchsploit for '%s'") %(squery) + bcolors.ENDC
    command = "searchsploit %s" % (squery)
    results = subprocess.check_output(command, shell=True)
    print results
    squest = raw_input("Would you like a copy of a specific exploit? ")
    if squest == "y":
       copy_sploit(scanip, location)
    elif squest == "n":
       os.system('clear')
       print "No problem...! "
       print ""

def copy_sploit(scanip, location):
    CHANGEDIR = os.chdir(location + scanip + "/exploits/")
    print ""
    scopy = raw_input("Please enter exploit ID, i.e 40744.py or 66.c: ")
    print ""
    print bcolors.OKGREEN + ("[+] Copying exploit to local directory") + bcolors.ENDC
    command = "searchsploit -m %s" % (scopy)
    results = subprocess.check_output(command, shell=True)
    print ""
    print results

def open_sploit(scanip, location):
    print bcolors.WARNING + "[+] Locating exploit folder..." + bcolors.ENDC
    command = "nautilus %s%s/exploits/" %(location, scanip)
    results = subprocess.check_output(command, shell=True)
    print bcolors.OKGREEN + "[+] Exploit folder is now open!" + bcolors.ENDC

def soptions(scanip, location):
   choice = 1
   loop = 1
   while loop == 1:
      smenu(scanip)
      choice = int(raw_input("Please enter option: "))
      print ""
      if choice == 1:
          check_sploit(scanip, location)
      if choice == 2:
          copy_sploit(scanip, location)
      if choice == 3:
          open_sploit(scanip, location)
      elif choice == 4:
          os.system('clear')
          loop = 0
          choice = 0



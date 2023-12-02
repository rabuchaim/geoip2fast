#!/usr/bin/env python3

##──── This test shows what GeoIP2Fast has that Maxmind's MMDB doesn't, and vice versa  ──────────────────────────────────────────
##──── Download the file "GeoLite2-Country.mmdb" from Maxmind website and put it in the same directory ───────────────────────────
##──── of this script to run the test ────────────────────────────────────────────────────────────────────────────────────────────
##──── if you have geoipupdate installed, you should already have this file in the directory /var/lib/GeoIP/ It wIll works too ───

##──── The BLUE lines shows that GeoIP2Fast result is the same as the Maxmind result with MMDB files. ────────────────────────────
##──── Lines in RED means that there is a divergence between the base of GeoIP2Fast and Maxmind. ─────────────────────────────────
##──── You can confirm 'who is right' using whois or geoiplookup application in linux ────────────────────────────────────────────

import os, sys, re, ctypes
from geoip2fast import GeoIP2Fast
from random import randrange

try:
    import geoip2.database             # pip install geoip2    
except:
    print("Run 'pip install geoip2' first and try again")
    sys.exit(1)

def cRed(msg):
    return '\033[91m'+msg+'\033[0m'
def cBlue(msg):
    return '\033[94m'+msg+'\033[0m'
    
def create_iplist(quant):
    a_list = []
    for I in range(quant):
        IP = f"{randrange(1,224)}.{randrange(0,254)}.{randrange(0,254)}.{randrange(0,254)}"
        a_list.append(IP)
        if I % 5000 == 0:
            print("\rGenerating random IPs: "+str(I+1),end="")
    print(f"\rGenerating randomically {len(a_list)} IPs...")
    return a_list

def get_geoip_from_mmdb(ipaddr)->str:
    try:
        response = reader.country(ipaddr)
        return str(response.country.iso_code)
    except Exception as ERR:
        # print(str(ERR))
        return "--"

if __name__ == "__main__":
    GeoIP = GeoIP2Fast(verbose=True)    
    if os.stat('/var/lib/GeoIP/GeoLite2-Country.mmdb').st_mode:
        reader = geoip2.database.Reader('/var/lib/GeoIP/GeoLite2-Country.mmdb',mode=geoip2.database.MODE_MMAP)
    else:
        reader = geoip2.database.Reader('GeoLite2-Country.mmdb',mode=geoip2.database.MODE_MMAP) 
    
    gIpList = create_iplist(100000)
    counter = 0
    print("")
    print("This test shows what GeoIP2Fast has that Maxmind's MMDB files doesn't")
    print("")
    print(f"{'IP address'.center(20)}|{'from GeoIP2Fast'.center(20)}|{'from MMDB file'.center(20)}|")
    for IP in gIpList:
        geoip_info = GeoIP.lookup(IP)
        getFromLocal = geoip_info.country_code
        getFromMMDB = get_geoip_from_mmdb(IP)
                
        if getFromLocal == "":
            getFromLocal = "--"

        logString = (f"{('IP: '+IP).ljust(20)}|{str(getFromLocal).center(20)}|{str(getFromMMDB).center(20)}|")

        if getFromMMDB != getFromLocal:
            print(cRed("\r"+logString))
            counter += 1
        else:
            print(cBlue("\r"+logString),end="")

        # clear the last line
        if IP == gIpList[-1]:
            print("\r".ljust(105," "),end="")            
    
    print("\n")
    print("Lines in RED means that there are a divergence between the base of GeoIP2Fast and Maxmind.")
    print("You can confirm 'who is right' checking different sources like a geoip lookup application ")
    print("like geoiplookup (ubuntu: apt install geoip-bin) or a whois service (ubuntu: apt install whois)")
    print("")
    print("     From %s random IP addresses tested, were found %s IP addresses"%((re.sub(r'(?<!^)(?=(\d{3})+$)', r'.', str(len(gIpList)))),counter))
    print("     with different geo information from Maxmind MMDB file.")    
    print("\nUsually they are IPs assigned to continents (EUrope, ASia, etc). If it's a lot of IPs,")
    print("I think either your geoip2fast.dat.gz is way out of date or your Maxmind MMDB is out of date.")
    print("It is acceptable to have < 0.1% of divergence. Remembering that the source of GeoIP2Fast ")
    print("is Maxmind Geolite2, but in the CSV version.")
          
    print("")

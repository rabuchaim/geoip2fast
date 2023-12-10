#!/usr/bin/env python3
# encoding: utf-8
# -*- coding: utf-8 -*-
import sys
from geoip2fast import GeoIP2Fast

if __name__ == "__main__":
    print("")    
    
    GEOIP = GeoIP2Fast(verbose=True,geoip2fast_data_file="")
    
    print("\n - If the IP address belongs to a private/special/reserved network, returns country_code == '--'")
    print(" - If the IP address belongs to a network that is not in out database, returns country_code == '--' and country_name == 'not found in database")
    print(" - If the IP address is invalid, returns an empty country_code and the error message in country_name property.\n")
    
    for IP in ['0.0.0.1','266.266.266.266','192,0x0/32','1.2.3.4/32','1.2.3.4','2.2.2.2','127.0.0.10','8.4.4.2','13.107.195.95',
               '8.8.8.8','10.20.30.40','88.221.89.159', '54.233.138.252','23.46.92.180','130.228.130.204','52.96.91.34', 
               '220.30.45.60','57.242.128.144','200.25.31.45','192.168.10.10','200.200.200.200','11.22.33.44','200.147.0.20 ']:
        geoip = GEOIP.lookup(IP)
        print("> "+IP.ljust(15)+" "+str(geoip.country_code).ljust(3)+str(geoip.country_name).ljust(35)+ \
            " ["+geoip.elapsed_time+"]\tAfter cache: ["+GEOIP.lookup(IP).elapsed_time+"] "+geoip.cidr)

    print("")

    result = GEOIP.lookup("200.204.0.10")
    print(result)

    # Before call the function get_hostname(), 'hostname' property will always be empty
    print("Hostname: "+result.hostname+"\t\t\t << must be empty before call result.get_hostname()")
    result.get_hostname()

    print(result)

    # to work with output as a dict, use the function to_dict()
    print(result.to_dict()['country_code'],result.to_dict()['country_name'])

    # To pretty print the object result like json.dumps()
    result = GEOIP.lookup("200.204.0.138")
    result.get_hostname()
    print(result.pp_json(indent=3,sort_keys=False))

    # info about internal cache
    print(GEOIP.cache_info())

    # clear the internal cache
    print(GEOIP.clear_cache())

    # info about internal cache
    print(GEOIP.cache_info())

    # to check the date of the CSV files used to create the .dat file
    print(GEOIP.get_source_info())
    
    print("")

    sys.exit(0)
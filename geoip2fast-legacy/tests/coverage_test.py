#!/usr/bin/env python3
import sys
from geoip2fast import GeoIP2Fast

GeoIP = GeoIP2Fast(verbose=True)
    
if __name__ == "__main__":
    print("")
    print("This test checks how many IP addresses are inside all networks included in geoip2fast.dat.gz and ")
    print("\ncompare with all 4.294.967.296 IPv4 on the internet... execute \"./coverage.py -v\" to see more details.")
    print("")
    GeoIP.calculate_coverage(print_result=True,verbose=bool('-v' in sys.argv))
    print("")
#!/usr/bin/env python3
from geoip2fast import GeoIP2Fast

GeoIP = GeoIP2Fast(verbose=True)

print("\n- Starting 'lookups per second' test...\n")
GeoIP.calculate_speed(print_result=True)
print("")

#!/usr/bin/env python3
from geoip2fast import GeoIP2Fast
from random import randrange
from time import sleep

MAX_IPS = 1000000
GeoIP = GeoIP2Fast(verbose=True)

print("\n- Starting a %d random IP test in"%(MAX_IPS),end="")
print(" 3...",end="")
sleep(1)
print(" 2...",end="")
sleep(1)
print(" 1...",end="")
sleep(1)
print("\n")

avgList, avgCacheList = [], []

total = 0
while total < MAX_IPS:
    IP = f"{randrange(1,223)}.{randrange(0,254)}.{randrange(0,254)}.{randrange(0,254)}"
    result = GeoIP.lookup(IP)
    avgList.append(float(result.elapsed_time.split(" ")[0]))
    total += 1
    cachedResult = GeoIP.lookup(IP)
    avgCacheList.append(float(cachedResult.elapsed_time.split(" ")[0]))
    print(f"IP {result.ip.ljust(20)}{result.country_code.ljust(4)}{result.country_name.ljust(40)}[{result.elapsed_time}] - Cached [{cachedResult.elapsed_time}]")
print("")
print("Test with %d randomic IP addresses."%(MAX_IPS))
print("\t- Average Lookup Time: %.9f seconds. "%(sum(avgList)/MAX_IPS))
print("\t- Average Cached Lookups: %.9f seconds. "%(sum(avgCacheList)/MAX_IPS))
print("")


#!/usr/bin/env python3
# encoding: utf-8
# -*- coding: utf-8 -*-
"""
GeoIP2Fast - Version: v1.0.5 - 20/Sep/2023

Author: Ricardo Abuchaim - ricardoabuchaim@gmail.com
        https://github.com/rabuchaim/geoip2fast/

License: MIT
"""
"""                                                                  
.oPYo.               o  .oPYo. .oPYo.  ooooo                 o  
8    8               8  8    8     `8  8                     8  
8      .oPYo. .oPYo. 8 o8YooP'    oP' o8oo   .oPYo. .oPYo.  o8P 
8   oo 8oooo8 8    8 8  8      .oP'    8     .oooo8 Yb..     8  
8    8 8.     8    8 8  8      8'      8     8    8   'Yb.   8  
`YooP8 `Yooo' `YooP' 8  8      8ooooo  8     `YooP8 `YooP'   8  
:....8 :.....::.....:..:..:::::.......:..:::::.....::.....:::..:
:::::8 :::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::..:::::::::::::::::::::::::::::::::::::::::::::::::::::::::
"""
"""
What's new in v1.0.5 - 20/Sep/2023
- geoip2fast.dat.gz updated with MAXMIND:GeoLite2-Country-ASN-CSV_20230919
- faster than ever!!! a lookup around ~0.00001
- A new option in geoip2dat to create .dat.gz with asn support: --asn-dir
- ASN support - the dat file already has support for ASN of the network 
  ranges. The footprint was incresed to 44Mb. The speed is the same.
- If you want, you can create an another dat file only with country data,
  just use the option --country-dir without the option --asn-dir
- geoip2dat updated too! older versions won't work anymore. Sorry.
- more flowers

What's new in v1.0.4 - 13/Sep/2023
- geoip2fast.dat.gz updated with MAXMIND:GeoLite2-Country-CSV_20230912
- fix in search of IPs that end in ".0"
- fix in _locate_database() function that search dat.gz file in
  $current_application_file path and library path 
- added some cli parameters: --speed-test, --self-test, and --coverage 
  ( try: ./geoip2fast.py --coverage -v to see all networks included in 
  dat file. )
- added a parameter in tests: --missing-ips  (take care, uses 100% of CPU)
- geoip2dat updated too! older versions won't work anymore. Sorry.
- more flowers

What's new in v1.0.3 - 08/Sep/2023
- geoip2fast.dat.gz updated with MAXMIND:GeoLite2-Country-CSV_20230908
- IMPROVED SPEED!! >100.000 LOOKUPS PER SECOND! GeoIP2Flash!
- geoip2fast.dat.gz decreased to ONE MEGABYTE! (-60%)
- RAM footprint dropped to 25 MiB! (-50%)
- load time around ~0,05 seconds! (-50%)
- the number of networks and content still the same, we just 
  converted all data to integers and sliced the lists a lot! This
  was necessary to implement the ASN data (not yet).
- geoip2dat updated to create the new dat file structure
- inserted a tag in dat file to record the version.
- as requested, property elapsed_time_hostname for hostnames lookups

What's new in v1.0.2 - 04/Sep/2023
- geoip2fast.dat.gz updated with MAXMIND:GeoLite2-Country-CSV_20230901
- fully tested with Python 3.11.5. Much faster than 3.10.12 >100K lookups/sec.
- fix encoding of pp_json() method. Now it's showing all chars as it is.
- in verbose mode it is now showing the memory footprint.
- new test files at /usr/local/lib/python3.10/dist-packages/geoip2fast/tests/
- new class CIDRDetail will be used to create gepip2fast.dat file
- geoip2dat - a script to import Maxmind-Country-CSV into geoip2fast.dat.gz.
  You can update your geoip2fast.dat.gz file whenever you want. It should work 
  with paid version also. Please let me know if there are any problems.
- put some flowers;

What's new in v1.0.1 - 1º/Sep/2023
- geoip2fast.dat.gz updated with MAXMIND:GeoLite2-Country-CSV_20230901
- improved speed in >20%! removed ipaddress module. Now we do some IP calcs.
- new methods to set the error code for the situations PRIVATE NETWORKS and for 
  NETWORKS NOT FOUND:
    GeoIP2Fast.set_error_code_private_networks(new_value) 
    GeoIP2Fast.set_error_code_network_not_found(new_value)
- new method to calculate the current speed. Returns a value of current lookups per 
  seconds or print a formatted result:
    GeoIP2Fast.calculate_speed(print_result=True)
- new method to calculate how many IPv4 of all internet are covered by geoip2fast.dat 
  file. Returns a percentage relative to all possible IPv4 on the internet or print a 
  formatted result. Useful to track the changes in getip2fast.dat.gz file:
    GeoIP2Fast.calculate_coverage(print_result=True)
"""

__version__ = "1.0.5"

import sys, os, json, gzip, pickle, json, math
from pprint import pprint as pp
from struct import unpack, pack
from random import randint
from functools import lru_cache
from time import perf_counter, sleep
from bisect import bisect as geoipBisect
from socket import inet_aton, inet_ntoa, setdefaulttimeout, gethostbyaddr

import geoip2fast as _ 
GEOIP2FAST_DAT_GZ_FILE = os.path.join(os.path.dirname(_.__file__),"geoip2fast.dat.gz")
# GEOIP2FAST_ASN_DAT_GZ_FILE = os.path.join(os.path.dirname(_.__file__),"geoip2fast-asn.dat.gz")

##──── Define here what do you want to return as 'country_code' if one of these errors occurs ────────────────────────────────────
GEOIP_ECCODE_PRIVATE_NETWORKS       = "--"
GEOIP_ECCODE_NETWORK_NOT_FOUND      = "--"
GEOIP_ECCODE_INVALID_IP             = ""
GEOIP_ECCODE_LOOKUP_INTERNAL_ERROR  = ""
GEOIP_NOT_FOUND_STRING              = "<not found in database>"
##──── ECCODE = Error Country Code ───────────────────────────────────────────────────────────────────────────────────────────────

DEFAULT_LRU_CACHE_SIZE = 1000

sys.tracebacklimit = 0

middot                  = "\xb7"

##──── To enable DEBUG flag just export an environment variable GEOIP2FAST_DEBUG with any value ──────────────────────────────────
##──── Ex: export GEOIP2FAST_DEBUG=1 ─────────────────────────────────────────────────────────────────────────────────────────────
_DEBUG = bool(os.environ.get("GEOIP2FAST_DEBUG",False))

os.environ["PYTHONWARNINGS"]    = "ignore"
os.environ["PYTHONIOENCODING"]  = "UTF-8"        

reservedNetworks = {
    "0.0.0.0/8":         {"01":"Reserved for self identification"},
    "10.0.0.0/8":        {"02":"Private Network Class A"},
    "100.64.0.0/10":     {"03":"Reserved for Shared Address Space"},
    "127.0.0.0/8":       {"04":"Localhost"},
    "169.254.0.0/16":    {"05":"APIPA Automatic Priv.IP Addressing"},
    "172.16.0.0/12":     {"06":"Private Network Class B"},
    "192.0.0.0/29":      {"07":"Reserved IANA"},
    "192.0.2.0/24":      {"08":"Reserved for TEST-NET"},
    "192.88.99.0/24":    {"09":"Reserved for 6to4 Relay Anycast"},
    "192.168.0.0/16":    {"10":"Private Network Class C"},
    "198.18.0.0/15":     {"11":"Reserved for Network Benchmark"},
    "224.0.0.0/4":       {"12":"Reserved Multicast Networks"},
    "240.0.0.0/4":       {"13":"Reserved for future use"},
    "255.255.255.255/32":{"14":"Reserved for broadcast"}
    }

##──── ANSI COLORS ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def cGrey(msg): return '\033[90m'+str(msg)+'\033[0m'
def cWhite(msg): return '\033[97m'+str(msg)+'\033[0m'
def cYellow(msg): return '\033[93m'+str(msg)+'\033[0m'
def cDarkYellow(msg): return '\033[33m'+str(msg)+'\033[0m'

##──── DECORATOR TO EXEC SOMETHING BEFORE AND AFTER A METHOD CALL. FOR TESTING AND DEBUG PURPOSES ──────────────────────────────
def print_elapsed_time(method):
    def decorated_method(self, *args, **kwargs):
        startTime = perf_counter()
        result = method(self, *args, **kwargs)  
        print(str(method)+" ("+str(*args)+") [%.9f sec]"%(perf_counter()-startTime))
        return result
    return decorated_method

##──── Function to check the memory use ────────────────────────────────────────────────────────────────────────────────────────
def get_mem_usage()->float:
    ''' Memory usage in MiB '''
    try:
        with open('/proc/self/status') as f:
            memusage = f.read().split('VmRSS:')[1].split('\n')[0][:-3]
    except FileNotFoundError:
        return 0.0
    return float(memusage.strip()) / 1024

##──── GeoIP2Fast Exception Class ────────────────────────────────────────────────────────────────────────────────────────────────    
class GeoIPError(Exception):
    def __init__(self, message):
        self.message = message
    def __str__(self):
        return self.message
##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

##──── Number os possible IPs in a network range. (/0, /1 .. /8 .. /24 .. /30, /31, /32) ─────────────────────────────────────
##──── Call the index of a list. Ex. numIPs[24] (is the number os IPs of a network range class C /24) ──────────────────────
numIPs = sorted([2**num for num in range(0,33)],reverse=True) # from 0 to 32
numIPs.append(0)
##──── numHosts is the numIPs - 2 ────────────────────────────────────────────────────────────────────────────────────────────────
numHosts = sorted([(2**num)-2 for num in range(0,33)],reverse=True) # from 0 to 32

##──── Calculate information about a CIDR ────────────────────────────────────────────────────────────────────────────────────────
@lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE)
class CIDRDetail(object):
    """An object to calculate some information about a CIDR, with some properties
       calculated on demand. This is necessary just because we need the first and last
       IP of a network converted to integer and the number of hosts used in coverage test.
       
       There are a lot of ways to get this information using ipaddress, netaddr, etc, but this
       is the fastest method tested.
    """   
    def __init__(self,CIDR):  # CIDR like 1.2.3.0/24, 10.0.0.0/8
        addr, nlen = CIDR.split('/')
        self.cidr = CIDR
        self.nlen = int(nlen)   # network length
        self.addr = [int(oct) for oct in addr.split(".")]
        self.mask = [( ((1<<32)-1) << (32-self.nlen) >> i ) & 255 for i in reversed(range(0, 32, 8))]
        self.netw = [self.addr[i] & self.mask[i] for i in range(4)]
        self.bcas = [(self.addr[i] & self.mask[i]) | (255^self.mask[i]) for i in range(4)]
    @property
    def first_ip(self)->str:
        return str(self.netw[0])+"."+str(self.netw[1])+"."+str(self.netw[2])+"."+str(self.netw[3])
    @property
    def last_ip(self)->str:
        return str(self.bcas[0])+"."+str(self.bcas[1])+"."+str(self.bcas[2])+"."+str(self.bcas[3])
    @property
    def first_ip2int(self)->int:
        return unpack("!I", inet_aton(str(self.netw[0])+"."+str(self.netw[1])+"."+str(self.netw[2])+"."+str(self.netw[3])))[0]
    @property
    def last_ip2int(self)->int:
        return unpack("!I", inet_aton(str(self.bcas[0])+"."+str(self.bcas[1])+"."+str(self.bcas[2])+"."+str(self.bcas[3])))[0]
    @property
    def num_ips(self)->int:
        return numIPs[self.nlen]
    @property
    def num_hosts(self)->int:
        return numHosts[self.nlen]
##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
class GeoIPDetail(object):
    """Object to store the information obtained by searching an IP address
    """    
    def __init__(self, ip, country_code="", country_name="", cidr="", is_private=False, asn_name="", elapsed_time=""):
        self.ip = ip
        self.country_code = country_code
        self.country_name = country_name
        self.cidr = cidr
        self.hostname = ""
        self.is_private = is_private
        self.asn_name = asn_name
        self.elapsed_time = elapsed_time
    def __str__(self):
        return f"{self.__dict__}"
    def __repr__(self):
        return f"{self.to_dict()}"    
    def get_hostname(self,dns_timeout=0.1):
        """Call this function to set the property 'hostname' with a socket.gethostbyaddr(ipadr) dns lookup.

        Args:
            dns_timeout (float, optional): Defaults to 0.1.

        Returns:
            str: the hostname if success or an error message between < >
        """
        try:
            startTime = perf_counter()
            setdefaulttimeout(dns_timeout)
            result = gethostbyaddr(self.ip)[0]
            self.hostname = result if result != self.ip else ""
            self.elapsed_time_hostname = "%.9f sec"%(perf_counter()-startTime)
            return self.hostname
        except OSError as ERR:
            self.hostname = f"<{str(ERR.strerror)}>"
            return self.hostname
        except Exception as ERR:
            self.hostname = "<dns resolver error>"
            return self.hostname        
    def to_dict(self):
        """To use the result as a dict

        Returns:
            dict: a dictionary with result's properties 
        """
        try:
            d = {
                "ip": self.ip,
                "country_code": self.country_code,
                "country_name": self.country_name,
                "cidr": self.cidr,
                "hostname":self.hostname,
                "is_private": self.is_private,
                }
            try:
                a = self.asn_name
                d['asn_name'] = self.asn_name
            except:
                pass
            d['elapsed_time'] = self.elapsed_time
            try:
                a = self.elapsed_time_hostname
                d['elapsed_time_hostname'] = self.elapsed_time_hostname
            except:
                pass
            return d
        except Exception as ERR:
            raise GeoIPError("Failed to_dict() %a"%(str(ERR)))
    def pp_json(self,indent=3,sort_keys=False,print_result=False):
        """ A pretty print for json

        If *indent* is a non-negative integer, then JSON array elements and object members will be pretty-printed with that indent level. An indent level of 0 will only insert newlines. None is the most compact representation.

        If *sort_keys* is true (default: False), then the output of dictionaries will be sorted by key.

        If *print_result* is True (default: False), then the output of dictionaries will be printed to stdout, otherwise a one-line string will be silently returned.

        Returns:
            string: returns a string to print.            
        """
        try:
            dump = json.dumps(self.to_dict(),sort_keys=sort_keys,indent=indent,ensure_ascii=False)
            if print_result == True:
                print(dump)
            return dump
        except Exception as ERR:
            raise GeoIPError("Failed pp_json() %a"%(str(ERR)))
    
            
class GeoIP2Fast(object):    
    """
    Creates the object that will load data from the database file and make the requested queries.

    - Usage:
        from geoip2fast import GeoIP2Fast
        
        myGeoIP = GeoIP2Fast(verbose=False,geoip2fast_data_file="")
        
        result = myGeoIP.lookup("8.8.8.8")
        
        print(result.country_code)
        
    - *geoip2fast_data_file* is used to specify a different path of file geoip2fast.dat.gz. If empty, the default paths will be used.
    
    - Returns *GEOIP_ECCODE_INVALID_IP* as country_code if the given IP is invalid

    - Returns *GEOIP_ECCODE_PRIVATE_NETWORKS* as country_code if the given IP belongs to a special/private/iana_reserved network
    
    - Returns *GEOIP_ECCODE_NETWORK_NOT_FOUND* as country_code if the network of the given IP wasn't found.

    - Returns *GEOIP_ECCODE_LOOKUP_INTERNAL_ERROR* as country_code if something eal bad occurs during the lookup function. Try again with verbose=True

    - To use the result as a dict: 
    
        result.to_dict()['country_code']
    """    
    def __init__(self, verbose=False, geoip2fast_data_file=""):
        global startMem  # declared as global to be used at function _load_data()
        startMem = get_mem_usage()
        self.data_file = ""
        self.verbose = verbose
        self._load_data_text = "" 
        ##──── Swap functions code at __init__ to avoid "if verbose=True" and save time ──────────────────────────────────────────────────
        if _DEBUG == False:
            self._print_debug = self.__print_verbose_empty
        if verbose == False:
            self._print_verbose = self.__print_verbose_empty
        ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────        
        self.error_code_private_networks        = GEOIP_ECCODE_PRIVATE_NETWORKS
        self.error_code_network_not_found       = GEOIP_ECCODE_NETWORK_NOT_FOUND
        self.error_code_invalid_ip              = GEOIP_ECCODE_INVALID_IP
        self.error_code_lookup_internal_error   = GEOIP_ECCODE_LOOKUP_INTERNAL_ERROR
        ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        self.is_loaded = False
        
        if geoip2fast_data_file != "":
            try:
                if os.is_file(geoip2fast_data_file) == True:
                    self.data_file = geoip2fast_data_file
            except Exception as ERR:
                raise GeoIPError("Unable to access the specified file %s. %s"%(geoip2fast_data_file,str(ERR)))
            
        self._load_data(self.data_file, verbose)
    ##──── Function used to avoid "if verbose == True". The code is swaped at __init__ ───────────────────────────────────────────────
    def __print_verbose_empty(self,msg):return
    def _print_debug(self,msg):
        print("[DEBUG] "+msg,flush=True)
    def _print_verbose(self,msg):
        print(msg,flush=True)
    ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def _locate_database_file(self,filename):
        try:
            curDir = os.path.join(os.path.abspath(os.path.curdir),filename) # path of your application
            libDir = os.path.join(os.path.dirname(_.__file__),filename)       # path where the library is installed
        except Exception as ERR:
            raise GeoIPError("Unable to determine the path of application %s. %s"%(filename,str(ERR)))
        try:
            os.stat(curDir).st_mode
            return curDir
        except Exception as ERR:            
            try:
                os.stat(libDir).st_mode 
                return libDir
            except Exception as ERR:
                raise GeoIPError("Unable to determine the path of library %s - %s"%(filename,str(ERR)))
    ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def _load_data(self, gzip_data_file:str, verbose=False)->bool:        
        global __DAT_VERSION__, databaseHash, geoipASNList, sliceInfo, geoipLocationDict, geoipMainList, geoipSourceInfo
        if self.is_loaded == True:
            return True   
        startLoadData = perf_counter()
        ##──── Try to locate the database file in the directory of the application that called GeoIP2Fast() ─────────────────────────
        ##──── or in the directory of the GeoIP2Fast Library ────────────────────────────────────────────────────────────────────────
        try:
            if gzip_data_file == "":
                gzip_data_file = GEOIP2FAST_DAT_GZ_FILE
                try:
                    databasePath = self._locate_database_file(os.path.basename(gzip_data_file))
                    if databasePath is False:
                        raise GeoIPError("1Unable to find GeoIP2Fast database file %s"%(os.path.basename(gzip_data_file)))
                    else:
                        self.data_file = databasePath
                except Exception as ERR:
                    raise GeoIPError("2Unable to find GeoIP2Fast database file %s %s"%(os.path.basename(gzip_data_file),str(ERR)))
        except Exception as ERR:
            raise GeoIPError("Failed at locate data file %s"%(str(ERR)))        
        ##──── Open the dat.gz file ──────────────────────────────────────────────────────────────────────────────────────────────────────
        try:
            try:
                inputFile = gzip.open(str(self.data_file),'rb')
            except:
                try:
                    inputFile = open(str(self.data_file).replace(".gz",""),'rb')
                    self.data_file = self.data_file.replace(".gz","")
                except Exception as ERR:
                    raise GeoIPError(f"1Unable to find {gzip_data_file} or {gzip_data_file} {str(ERR)}\n")
        except Exception as ERR:
            raise GeoIPError(f"Failed to 'load' GeoIP2Fast! the data file {gzip_data_file} appears to be invalid or does not exist! {str(ERR)}\n")
            ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────        
            ##──── Load the dat.gz file into memory ──────────────────────────────────────────────────────────────────────────────────────────
            ##──── MODEL OF DATAFILE ─────────────────────────────────────────────────────────────────────────────────────────────────────────
            # database = [__DAT_VERSION__,    # integer
            #             listLocation,       # list      "country_code:country_name"
            #             listAsnNames,       # list 
            #             geoipList,          # geoipList = [mainIndex, mainList, mainListCodes, mainListNetLength, mainIndexASN, mainListASN, mainListASNLength]
            #             hashMD5,            # hashmd5 = mainIndex + ":" + lenght of all records
            #             str(sliceInfo),     # string (dict = 'num_keys','total_networks','slice_size''length_last_list')
            #             _SOURCE_INFO]       # string 
        if '-vvv' in sys.argv: 
            print(f"Using datafila: {gzip_data_file}")
            sys.exit(0)
        try:
            __DAT_VERSION__, _geoipListLocation, geoipASNList, geoipMainList, databaseHash, sliceInfo, geoipSourceInfo = pickle.load(inputFile)
            if __DAT_VERSION__ != 105:
                raise GeoIPError(f"Failed to pickle the data file {gzip_data_file}. Reason: Invalid version - requires 105, current {str(__DAT_VERSION__)}\n")
            geoipLocationDict = {item.split(":")[0]:item.split(":")[1] for item in _geoipListLocation}
            inputFile.close()
            del _geoipListLocation
            del inputFile
        except Exception as ERR:
            raise GeoIPError(f"Failed to pickle the data file {gzip_data_file} {str(ERR)}\n")
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

        ##──── Warming-up ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        try:
            [self._main_index_lookup(iplong) for iplong in [4294967295]]
        except Exception as ERR:
            raise GeoIPError("Failed at warming-up... exiting... %s"%(str(ERR)))
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        
        ##──── Load Time Info ──────────────────────────────────────────────────────────────────────────────────────────────────────────
        try:
            totalLoadTime = (perf_counter() - startLoadData)
            totalMemUsage = (get_mem_usage() - startMem)
            self._load_data_text = f"GeoIP2Fast v{__version__} is ready! {os.path.basename(gzip_data_file)} "+ \
                "loaded with %s networks in %.5f seconds and using %.2f MiB."%(str(self._total_networks()),totalLoadTime,totalMemUsage)
            self._print_verbose(self._load_data_text)
        except Exception as ERR:
            raise GeoIPError("Failed at the end of load data %s"%(str(ERR)))
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        self.is_loaded = True
        return True

    @property
    def startup_line_text(self):
        ##──── Returns the text of _load_data() in case you want to know without set verbose=True ───────────────────────────────────────────
        ##──── Like: GeoIP2Fast v1.X.X is ready! geoip2fast.dat.gz loaded with XXXXXX networks in 0.0000 seconds and using YY.ZZ MiB. ───────
        return self._load_data_text

    @lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=True)
    def _main_index_lookup(self,iplong):
        try:
            matchRoot = geoipBisect(geoipMainList[0],iplong)-1
            matchChunk = geoipBisect(geoipMainList[1][matchRoot],iplong)-1        
            first_ip2int = geoipMainList[1][matchRoot][matchChunk]
            last_ip2int = first_ip2int + numIPs[geoipMainList[3][matchRoot][matchChunk]] - 1
            return matchRoot, matchChunk, first_ip2int, last_ip2int
        except Exception as ERR:
            return GeoIPError("Failed at _main_index_lookup: %s"%(str(ERR)))
    
    @lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=True)
    def _cidr_lookup(self,first_ip2int,cidr_suffix):
        try:
            return str(self._int2ip(first_ip2int))+"/"+str(cidr_suffix)
        except Exception as ERR:
            return GeoIPError("Failed at _cidr_lookup: %s"%(str(ERR)))

    @lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=True)
    def _lastip_lookup(self,first_ip2int,cidr_suffix):
        try:
            return first_ip2int + numIPs[cidr_suffix] - 1
        except Exception as ERR:
            return GeoIPError("Failed at _lastip_lookup: %s"%(str(ERR)))
            
    @lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=True)
    def _asn_lookup(self,iplong):
        try:
            matchRoot = geoipBisect(geoipMainList[4],iplong)-1
            matchChunk = geoipBisect(geoipMainList[5][matchRoot],iplong)-1        
            return geoipASNList[geoipMainList[6][matchRoot][matchChunk]]
        except Exception as ERR:
            return ""
                        
    @lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=True)
    def _country_lookup(self,match_chunk):
        try:
            country_code = list(geoipLocationDict.keys())[match_chunk]
            country_name = geoipLocationDict[country_code]            
            try:
                int(country_code)                                # On all PRIVATE/RESERVED networks, we put a number as a "isocode".
                country_code = self.error_code_private_networks  # If is possible to convert to integer, it means that the IP belongs to
                is_private = True                                # a private/reserved network and does not have a country_code,
            except:                                              # so change the country_code to '--' (self.error_code_private_networks)
                is_private = False                               # and set is_private to True, otherwise skip and set is_private to False            
            return country_code, country_name, is_private
        except Exception as ERR:
            return GeoIPError("Failed at _country_lookup: %s"%(str(ERR)))

    @lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=True)
    def _ip2int(self,ipaddr:str)->int:
        """
        Convert an IP Address into an integer number
        """    
        try:
            return unpack("!I", inet_aton(ipaddr))[0]
        except Exception as ERR:
            raise GeoIPError("Failed at ip2int: %s"%(str(ERR)))

    @lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=True)
    def _int2ip(self,ipaddr:int)->str:
        """
        Convert an integer to IP Address
        """    
        try:
            return inet_ntoa(pack("!I", ipaddr))
        except Exception as ERR:
            raise GeoIPError("Failed at int2ip: %s"%(str(ERR)))
            
    def set_error_code_private_networks(self,new_value)->str:
        """Change the GEOIP_ECCODE_PRIVATE_NETWORKS. This value will be returned in country_code property.

        Returns:
            str: returns the new value setted
        """
        global GEOIP_ECCODE_PRIVATE_NETWORKS
        try:
            self.error_code_private_networks = new_value
            GEOIP_ECCODE_PRIVATE_NETWORKS = new_value
            return new_value
        except Exception as ERR:
            raise GeoIPError("Unable to set a new value for GEOIP_ECCODE_PRIVATE_NETWORKS: %s "%(str(ERR)))
        
    def set_error_code_network_not_found(self,new_value)->str:
        """Change the GEOIP_ECCODE_NETWORK_NOT_FOUND. This value will be returned in country_code property.

        Returns:
            str: returns the new value setted
        """
        global GEOIP_ECCODE_NETWORK_NOT_FOUND
        try:
            self.error_code_network_not_found = new_value
            GEOIP_ECCODE_NETWORK_NOT_FOUND = new_value
            return new_value
        except Exception as ERR:
            raise GeoIPError("Unable to set a new value for GEOIP_ECCODE_NETWORK_NOT_FOUND: %s "%(str(ERR)))
        
    ##──── NO-CACHE: This function cannot be cached to don´t cache the elapsed timer. ────────────────────────────────────────────────────────────
    def lookup(self,ipaddr:str)->GeoIPDetail:
        """
        Performs a search for the given IP address in the in-memory database

        - Returns *GEOIP_ECCODE_INVALID_IP* as country_code if the given IP is invalid

        - Returns *GEOIP_ECCODE_PRIVATE_NETWORKS* as country_code if the given IP belongs to a special/private/iana_reserved network
            
        - Returns *GEOIP_ECCODE_NETWORK_NOT_FOUND* as country_code if the network of the given IP wasn't found.

        - Returns *GEOIP_ECCODE_LOOKUP_INTERNAL_ERROR* as country_code if something eal bad occurs during the lookup function. Try again with verbose=True

        - Returns an object called GeoIPDetail withm its properties: ip, country_code, country_name, cidr, hostname, is_private and elapsed_time
            
        - Usage:

            from geoip2fast import GeoIP2Fast
    
            myGeoIP = GeoIP2Fast()
            
            result = myGeoIP.lookup("8.8.8.8")
            
            print(result.country_code)

        """                    
        startTime = perf_counter()
        try:
            iplong = self._ip2int(ipaddr)
        except Exception as ERR:
            return GeoIPDetail(ipaddr,country_code=self.error_code_invalid_ip,\
                    country_name="<invalid ip address>",elapsed_time='%.9f sec'%(perf_counter()-startTime))
        try:
            matchRoot, matchChunk, first_ip2int, last_ip2int = self._main_index_lookup(iplong)
            if iplong > last_ip2int:
                return GeoIPDetail(ip=ipaddr,country_code=self.error_code_network_not_found, \
                            country_name=GEOIP_NOT_FOUND_STRING,elapsed_time='%.9f sec'%(perf_counter()-startTime))
            country_code, country_name, is_private = self._country_lookup(geoipMainList[2][matchRoot][matchChunk])
            cidr = self._cidr_lookup(first_ip2int,geoipMainList[3][matchRoot][matchChunk])
            try:
                asn_name = self._asn_lookup(iplong) # geoipMainList[4][matchRoot][matchChunk])                
            except:
                asn_name = ""
            ##──── SUCCESS! ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            return GeoIPDetail(ipaddr,country_code,country_name,cidr,is_private,asn_name,elapsed_time='%.9f sec'%((perf_counter()-startTime)))
            ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        except Exception as ERR:
            self._print_verbose("Lookup internal error: "+str(ERR))
            return GeoIPDetail(ip=ipaddr,country_code=self.error_code_lookup_internal_error,\
                    country_name="<internal lookup error>",elapsed_time='%.9f sec'%(perf_counter()-startTime))
            
    def clear_cache(self)->bool:
        """ 
        Clear the internal cache of lookup function
        
        Return: True or False
        """
        try:
            self._main_index_lookup.cache_clear()
            self._cidr_lookup.cache_clear()
            self._lastip_lookup.cache_clear()
            self._asn_lookup.cache_clear()
            self._country_lookup.cache_clear()
            self._ip2int.cache_clear()
            self._int2ip.cache_clear()
            return True
        except Exception as ERR:
            return False
        
    def cache_info(self):
        """ 
        Returns information about the internal cache of lookup function
        
        Usage: print(GeoIP2Fast.cache_info())
        
        Exemple output: CacheInfo(hits=18, misses=29, maxsize=10000, currsize=29)
        """
        try:    
            return ("main_index_lookup "+str(self._main_index_lookup.cache_info()),\
                "cidr_lookup "+str(self._cidr_lookup.cache_info()),\
                "lastip_lookup "+str(self._lastip_lookup.cache_info()),\
                "lastip_lookup "+str(self._asn_lookup.cache_info()),\
                "country_lookup "+str(self._country_lookup.cache_info()),\
                "ip2int "+str(self._ip2int.cache_info()),\
                "int2ip "+str(self._int2ip.cache_info())
                )
        except Exception as ERR:
            print(str(ERR))
            return
    
    def get_source_info(self):
        """
        Returns the information of the data source of geoip data.
        """
        return geoipSourceInfo
            
    def _total_networks(self):
        """
        Returns the number of all networks included in geoip2fast.dat.gz file
        """
        total = 0
        for a_list in geoipMainList[1]:
            total += len(a_list)
        return total
    
    def self_test(self):
        """
            Do a self-test with some random IPs
        """                
        # ip_list = ['223.130.10.1','266.266.266.266','192,0x0/32','127.0.0.10','10.20.30.40','200.204.0.10',
        #            '57.242.128.144','192.168.10.10','200.200.200.200','11.22.33.44','200.147.0.20 ']
        ip_list = ['223.130.10.1','266.266.266.266','192,0x0/32','10.20.30.40']
        random_iplist = []
        MAX_IPS = 26
        avgList, avgCacheList = [], []        
        for I in range(MAX_IPS):
            random_iplist.append(f"{self._int2ip(randint(16777216,3758096383))}")
        ip_list = (*ip_list,*random_iplist)
        for IP in ip_list:
            geoip = self.lookup(IP)
            avgList.append(float(geoip.elapsed_time.split(" ")[0]))
            cachedResult = self.lookup(IP)
            avgCacheList.append(float(cachedResult.elapsed_time.split(" ")[0]))    
            print("> "+cWhite(IP.ljust(15))+" "+str(geoip.country_code).ljust(3)+cWhite(str(geoip.country_name).ljust(33))+ \
                " ["+cWhite(geoip.elapsed_time)+"]  Cached > ["+cWhite(cachedResult.elapsed_time)+"] "+cachedResult.asn_name[:42])
        print("")
        print("Self-test with %s randomic IP addresses."%('{:,d}'.format(len(ip_list))))
        print("\t- Average Lookup Time: %.9f seconds. "%(sum(avgList)/len(ip_list)))
        print("\t- Average Cached Lookups: %.9f seconds. "%(sum(avgCacheList)/len(ip_list)))
        print("")

    def random_test(self):
        """
            Do a self-test with 1.000.000 of randomic IPs
        """        
        GeoIP = GeoIP2Fast(verbose=False)
        MAX_IPS = 1000000
        random_iplist = []
        startTime = perf_counter()
        for I in range(MAX_IPS):
            random_iplist.append(f"{self._int2ip(randint(16777216,3758096383))}")
        print(f"List of {'{:,d}'.format(MAX_IPS)} of randomic IPs created in {'%.2f seconds'%(perf_counter()-startTime)}")
        print("")
        for I in range(5,0,-1):
            print(f"\rStart in {I} second(s)...",end="")
            sleep(1)
        print("\r")
        avgList, avgCacheList = [], []
        startTime = perf_counter()
        for IP in random_iplist:
            geoip = GeoIP.lookup(IP)
            avgList.append(float(geoip.elapsed_time.split(" ")[0]))
            cachedResult = GeoIP.lookup(IP)
            avgCacheList.append(float(cachedResult.elapsed_time.split(" ")[0]))    
            print("> "+cWhite(IP.ljust(15))+" "+str(geoip.country_code).ljust(3)+cWhite(str(geoip.country_name).ljust(33))+ \
                " ["+cWhite(geoip.elapsed_time)+"]  Cached > ["+cWhite(cachedResult.elapsed_time)+"] ")
        print("")
        print("Random test with %s randomic IP addresses."%('{:,d}'.format(MAX_IPS)))
        print("\t- Average Lookup Time: %.9f seconds. "%(sum(avgList)/MAX_IPS))
        print("\t- Average Cached Lookups: %.9f seconds. "%(sum(avgCacheList)/MAX_IPS))
        print("")
               
    def show_missing_ips(self):
        """
            Scan database for network ranges without geographic information. 
        """        
        total_missing_ips = 0
        total_missing_networks = 0
        classDict = {}
        try:
            startTime = perf_counter()
            for N in range(len(geoipMainList[1])-1):
                for I in range(len(geoipMainList[1][N])-1):
                    first_iplong = geoipMainList[1][N][I]
                    first_ipstring = self._int2ip(geoipMainList[1][N][I])
                    last_iplong = geoipMainList[1][N][I] + numIPs[geoipMainList[3][N][I]] - 1
                    if first_iplong == 0:
                        old_last_iplong = last_iplong
                        continue
                    if first_iplong - old_last_iplong > 1:
                        miss_first_iplong = old_last_iplong + 1
                        miss_last_iplong = first_iplong - 1
                        missing_ips = miss_last_iplong - miss_first_iplong + 1
                        if math.log(missing_ips, 2).is_integer() == False:
                            cidr = cGrey("<unknown>".center(18))
                        else: # if number of missing IPs is power of 2
                            cidr = cWhite((first_ipstring+"/"+str(numIPs.index(missing_ips))).ljust(18))
                        if classDict.get(first_ipstring.split(".")[0],"X") == "X":
                            classDict[first_ipstring.split(".")[0]] = 0
                        classDict[first_ipstring.split(".")[0]] += missing_ips
                        total_missing_networks += 1
                        for IP in range(miss_first_iplong,miss_last_iplong+1):
                            test = self.lookup(self._int2ip(miss_first_iplong)).to_dict()
                            if test['country_code'] != "--":
                                classDict[first_ipstring.split(".")[0]] -= 1
                                missing_ips -= 1
                        print(f"From {cWhite(self._int2ip(miss_first_iplong).ljust(15))} to {cWhite(self._int2ip(miss_last_iplong).ljust(15))} > Network {cidr} > Missing IPs: {cWhite(missing_ips)}")
                        total_missing_ips += missing_ips
                    old_last_iplong = last_iplong
            total_missing_networks -= 13 # 14 special networks first IPs - 1 reserved for broadcast that is included in 240.0.0.0/4
            total_missing_ips += total_missing_networks # a difference for the last ip excluded to calc math.power of 2
            if '-v' in sys.argv:
                print("")
                classDict = dict(sorted(classDict.items(),key=lambda x:int(x[1]), reverse=True))
                classDictOne = {k:v for k,v in classDict.items() if v == 1}
                classDictTwo = {k:v for k,v in classDict.items() if v == 2}
                classDict = {k:v for k,v in classDict.items() if v > 2}
                print("  > Missing IPs per network class:\n")
                for k,v in classDict.items():
                    print(f"    - Class {k}.0.0.0/8".ljust(25,middot)+": "+f"{'{:,d}'.format(v)}")
                if len(classDictTwo.keys()) > 0:
                    logString = "    - Class "
                    for key in classDictTwo.keys():
                        logString += key+".0.0.0/8, "
                        if (list(classDictTwo.keys()).index(key) + 1) % 5 == 0:
                            logString += "\n      "
                    logString = logString[:-2]+"..: 2 (each one)"
                    print(logString)                    
                if len(classDictOne.keys()) > 0:
                    logString = "    - Class "
                    for key in classDictOne.keys():
                        logString += key+".0.0.0/8, "
                        if (list(classDictOne.keys()).index(key) + 1) % 5 == 0:
                            logString += "\n      "
                    logString = logString[:-2]+"..: 1 (each one)"
                    print(logString)
            print("")
            percentage = (total_missing_ips * 100) / numIPs[0]
            print(f">>> Valid IP addresses without geo information: {cYellow('{:,d}'.format(total_missing_ips))} (%.2f%% of all IPv4) [%.5f sec]"%(percentage,perf_counter()-startTime))
        except Exception as ERR:
            raise GeoIPError("Failed to show missing IPs information. %s"%(str(ERR)))
        
    def calculate_coverage(self,print_result=False,verbose=False)->float:
        """
            Calculate how many IP addresses are in all networks covered by geoip2fast.dat and compare with all 4.294.967.296 
            possible IPv4 addresses on the internet. 
        
            This include all reserved/private networks also. If remove them, need to remove them from the total 4.2bi and 
            the percetage will be the same.
            
            Run this function with "verbose=True" to see all networks included in geoip2fast.dat.gz file.
        
        Method: Get a list of all CIDR from geoip2fast.dat.gz using the function self._get_cidr_list(). For each CIDR, 
                calculates the number of hosts using the function self._get_num_hosts(CIDR) and sum all of returned values.
                Finally, the proportion is calculated in relation to the maximum possible number of IPv4 (4294967294).
                GeoIP2Fast will return a response for XX.XX% of all IPv4 on the internet.
        
        Returns:
            float: Returns a percentage compared with all possible IPs.
        """
        try:
            startTime = perf_counter()
            ipCounter = 0
            index = 0
            totalNetworks = 0
            for indexList in geoipMainList[3]:
                indexListCounter = 0
                for item in indexList:
                    totalNetworks += 1
                    startTimeCIDR = perf_counter()
                    num_ips = numIPs[item]
                    ipCounter += num_ips
                    if verbose and print_result == True:
                        IP = str(self._int2ip(geoipMainList[1][index][indexListCounter]))
                        CIDR = IP + "/" + str(item)
                        result = self.lookup(IP)
                        print(f"- Network: {cWhite(CIDR.ljust(19))} IPs: {cWhite(str(num_ips).ljust(10))} {result.country_code} {cWhite(result.country_name.ljust(35))} {'%.9f sec'%(perf_counter()-startTimeCIDR)}")
                    indexListCounter += 1
                index += 1                        
            ipCounter -= 1 # removing the last IP (255.255.255.255) that is already included in 240.0.0.0/4
            percentage = (ipCounter * 100) / numIPs[0]
            if print_result == True:
                if verbose: print("")
                print(f"Current IPv4 coverage: %.2f%% ({'{:,d}'.format(ipCounter)} IPs in %s networks) [%.5f sec]"%(percentage,totalNetworks,(perf_counter()-startTime)))
            return percentage
        except Exception as ERR:
            raise GeoIPError("Failed to calculate total IP coverage. %s"%(str(ERR)))
        
    def calculate_speed(self,print_result=False)->float:
        """Calculate how many lookups per second is possible.

        Method: generates a list of 1.000.000 of randomic IP addresses and do a GeoIP2Fast.lookup() on all IPs on this list. 
                It tooks a few seconds, less than a minute.

        Note: This function clear all cache before start the tests. And inside the loop generates a random IP address in runtime 
              and use the returned value to try to get closer a real situation of use. Could be 3 times faster if you prepare 
              a list of IPs before starts the loop and do a simple lookup(IP).
        
        Returns:
            float: Returns a value of lookups per seconds.
        """
        try:
            MAX_IPS = 1000000  # ONE MILLION
            self.clear_cache()   
            startTime = perf_counter()
            # COULD BE 3X FASTER IF YOU GENERATE A LIST WITH 1.000.000 IPs BEFORE LOOKUP.
            # BUT LET´S KEEP LIKE THIS TO SPEND SOME MILLISECONDS TO GET CLOSER A REAL SITUATION OF USE
            for NUM in range(MAX_IPS):
                IP = self._int2ip(randint(16777216,3758096383)) # from 1.0.0.0 to 223.255.255.255
                ipinfo = self.lookup(IP)
                XXXX = ipinfo.country_code # SIMULATE THE USE OF THE RETURNED VALUE
            total_time_spent = perf_counter() - startTime
            current_lookups_per_second = MAX_IPS / total_time_spent
            if print_result == True:
                print("Current speed: %.2f lookups per second (searched for %s IPs in %.9f seconds) [%.5f sec]"%(current_lookups_per_second,'{:,d}'.format(MAX_IPS),total_time_spent,perf_counter()-startTime))
            return current_lookups_per_second
        except Exception as ERR:
            raise GeoIPError("Failed to calculate current speed. %s"%(str(ERR)))
          
##──── A SIMPLE AND FAST CLI ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if '--speed-test' in sys.argv or '--speedtest' in sys.argv:
        geoip = GeoIP2Fast(verbose=True)
        print("\nCalculating current speed... wait a few seconds please...\n")
        geoip.calculate_speed(True)
        print("")
        sys.exit(0)
    if '--random-test' in sys.argv or '--randomtest' in sys.argv:
        geoip = GeoIP2Fast(verbose=True)
        print("")
        geoip.random_test()
        print("")
        sys.exit(0)
    if '--missing-ips' in sys.argv or '--missingips' in sys.argv:
        geoip = GeoIP2Fast(verbose=True)
        print("\nSearching for missing IPs...\n")
        geoip.show_missing_ips()
        print("")
        sys.exit(0)
    if '--self-test' in sys.argv or '--selftest' in sys.argv:
        geoip = GeoIP2Fast(verbose=True)
        print("\nStarting a self-test...\n")
        geoip.self_test()
        print("")
        sys.exit(0)
    if '--coverage' in sys.argv: 
        geoip = GeoIP2Fast(verbose=True)
        print("\nUse the parameter '-v' to see all networks included in your %s file.\n"%(GEOIP2FAST_DAT_GZ_FILE))
        geoip.calculate_coverage(True,bool('-v' in sys.argv))
        print("")
        sys.exit(0)
    ncmd = len(sys.argv)
    verbose_mode = False
    resolve_hostname = False
    if '-v' in sys.argv: 
        verbose_mode = True
        sys.argv.pop(sys.argv.index('-v'))
        ncmd -= 1
    if '-d' in sys.argv: 
        resolve_hostname = True
        sys.argv.pop(sys.argv.index('-d'))
        ncmd -= 1
    if len(sys.argv) > 1 and sys.argv[1] is not None and '-h' not in sys.argv:
        a_list = sys.argv[1].replace(" ","").split(",")
        if len(a_list) > 0:
            geoip = GeoIP2Fast(verbose=verbose_mode)
            for IP in a_list:
                result = geoip.lookup(IP)
                if resolve_hostname == True: result.get_hostname()
                result.pp_json(print_result=True)
    else:
        print(f"GeoIP2Fast v{__version__} Usage: {os.path.basename(__file__)} [-h] [-v] [-d] <ip_address_1>,<ip_address_2>,<ip_address_N>,...")
        if '-h' in sys.argv:
            print("""
Tests parameters:
  --self-test           Starts a self-test with some randomic IP addresses.
  --speed-test          Do a speed test with 1 million on randomic IP addresses.                                               
  --random-test         Start a test with 1.000.000 of randomic IPs and calculate a lookup average time.

  --coverage            Shows a statistic of how many IPs are covered by current dat file. 
  --coverage -v         With -v parameter will print all networks included in dat file.

  --missing-ips         Print all IP networks that we don´t have geo information.
  --missing-ips -v      Show more information about how many IPs are missing on each class.
             
More options:
  -d                    Resolve the DNS of given IP address.
  -h                    Show this help text.
  -v                    Verbose mode.
  -vvv                  Shows the location of current dat file.
  
  """)
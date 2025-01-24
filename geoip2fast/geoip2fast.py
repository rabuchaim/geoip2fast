#!/usr/bin/env python3
# encoding: utf-8
# -*- coding: utf-8 -*-
"""
GeoIP2Fast - Version v1.2.2

Author: Ricardo Abuchaim - ricardoabuchaim@gmail.com
        https://github.com/rabuchaim/geoip2fast/

License: MIT

.oPYo.               o  .oPYo. .oPYo.  ooooo                 o  
8    8               8  8    8     `8  8                     8  
8      .oPYo. .oPYo. 8 o8YooP'    oP' o8oo   .oPYo. .oPYo.  o8P 
8   oo 8oooo8 8    8 8  8      .oP'    8     .oooo8 Yb..     8  
8    8 8.     8    8 8  8      8'      8     8    8   'Yb.   8  
`YooP8 `Yooo' `YooP' 8  8      8ooooo  8     `YooP8 `YooP'   8  
:....8 :.....::.....:..:..:::::.......:..:::::.....::.....:::..:
:::::8 :::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::..:::::::::::::::::::::::::::::::::::::::::::::::::::::::::

What's new in v1.2.2 - 20/Jun/2024
- DAT files updated with MAXMIND:GeoLite2-CSV_20240618
- Removed the line "sys.tracebacklimit = 0" that was causing some problems 
  in Django. This line is unnecessary (https://github.com/rabuchaim/geoip2fast/issues/10)
- Maxmind inserted a new field into the CSV files called "is_anycast", and this broke 
  geoip2dat.py CSV reader. Insertion of the new field in the list of "fields" of
  the CSV reader that generates the .dat.gz files so that they can be updated.
- There are 2 reduced versions available for you to copy and paste
  into your own code without any dependencies and fast as always!
  Check these files in your library path:
    - geoip2fastmin.py (429 lines) 
    - geoip2fastminified.py (183 lines)
- As requested, 2 new methods to return a coverage of IPv4 and IPv6.
    def get_ipv4_coverage()->float
    def get_ipv6_coverage()->float
- New function get_database_info() that returns a dictionary with 
  detailed information about the data file currently in use.
- Made some adjustments to the --missing-ips and --coverage functions.  
- Now you can specify the data filename to be used on geoip2fast cli:
    geoip2fast geoip2fast-ipv6.dat.gz --self-test
    geoip2fast 9.9.9.9,1.1.1.1,2a10:8b40:: geoip2fast-asn-ipv6.dat.gz
- New functions to generate random IP addresses to be used in tests. 
  Returns a list if more than 1 IP is requested, otherwise returns a 
  string with only 1 IP address. If you request an IPv6 and the database
  loaded does not have IPv6 data, returns False. And the fuction of
  private address, returns an random IPv4 from network 10.0.0.0/8 or
  172.16.0.0/12 or 192.168.0.0/16.
    def generate_random_private_address(self,num_ips=1)->string or a list
    def generate_random_ipv4_address(self,num_ips=1)->string or a list
    def generate_random_ipv6_address(self,num_ips=1)->string or a list
- Removed functools.lru_cache. It is very useful when you have a function 
  that is repeated several times but takes a long time, which is not the 
  case of GeoIP2Fast where functions take milliseconds. On each call, 
  functools checks whether the value is already cached or not, and this 
  takes time. And we noticed that without functools and using the processor 
  and operating system's own cache makes GeoIP2Fast much faster without it
  even if you are searching for an IP for the first time.
  If you want to use lru_cache, you can uncomment the respective lines 
  of code. There are 5 lines commented with @functools.lru_cache 
- Put some flowers
"""
__appid__   = "GeoIP2Fast"
__version__ = "1.2.2"

import sys, os, ctypes, struct, socket, time, subprocess, random, binascii, functools
import urllib.request, urllib.error, urllib.parse, gzip, pickle, json, random, bisect, re, ipaddress
import geoip2fast as _ 

GEOIP2FAST_DAT_GZ_FILE = os.path.join(os.path.dirname(_.__file__),"geoip2fast.dat.gz")

##──── Define here what do you want to return if one of these errors occurs ─────────────────────────────────────────────────────
##──── ECCODE = Error Country Code ───────────────────────────────────────────────────────────────────────────────────────────────
GEOIP_ECCODE_PRIVATE_NETWORKS       = "--"
GEOIP_ECCODE_NETWORK_NOT_FOUND      = "--"
GEOIP_ECCODE_INVALID_IP             = ""
GEOIP_ECCODE_LOOKUP_INTERNAL_ERROR  = ""
GEOIP_NOT_FOUND_STRING              = "<not found in database>"
GEOIP_INTERNAL_ERROR_STRING         = "<internal lookup error>"
GEOIP_INVALID_IP_STRING             = "<invalid ip address>"
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
##──── Define here the size of LRU cache. Cannot be changed in runtime ───────────────────────────────────────────────────────────
DEFAULT_LRU_CACHE_SIZE = 1000
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
##──── Variables for automatic updates ───────────────────────────────────────────────────────────────────────────────────────────
GEOIP_UPDATE_DAT_URL                = "https://github.com/rabuchaim/geoip2fast/releases/download/LATEST/"
GEOIP_POSSIBLE_FILENAMES            = ['geoip2fast.dat.gz',
                                       'geoip2fast-ipv6.dat.gz',
                                       'geoip2fast-asn.dat.gz',
                                       'geoip2fast-asn-ipv6.dat.gz',
                                       'geoip2fast-city.dat.gz',
                                       'geoip2fast-city-ipv6.dat.gz',
                                       'geoip2fast-city-asn.dat.gz',
                                       'geoip2fast-city-asn-ipv6.dat.gz'
                                       ]
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
##──── To enable DEBUG flag just export an environment variable GEOIP2FAST_DEBUG with any value ──────────────────────────────────
##──── Ex: export GEOIP2FAST_DEBUG=1 ─────────────────────────────────────────────────────────────────────────────────────────────
_DEBUG = bool(os.environ.get("GEOIP2FAST_DEBUG",False))
os.environ["PYTHONWARNINGS"]    = "ignore"
os.environ["PYTHONIOENCODING"]  = "utf-8"        

##──── ANSI COLORS ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def cRed(msg): return '\033[91m'+str(msg)+'\033[0m'
def cBlue(msg): return '\033[94m'+str(msg)+'\033[0m'
def cGrey(msg): return '\033[90m'+str(msg)+'\033[0m'
def cWhite(msg): return '\033[97m'+str(msg)+'\033[0m'
def cYellow(msg): return '\033[93m'+str(msg)+'\033[0m'
def cDarkYellow(msg): return '\033[33m'+str(msg)+'\033[0m'

##──── DECORATOR TO EXEC SOMETHING BEFORE AND AFTER A METHOD CALL. FOR TESTING AND DEBUG PURPOSES ──────────────────────────────
def print_elapsed_time(method):
    def decorated_method(self, *args, **kwargs):
        startTime = time.perf_counter()
        result = method(self, *args, **kwargs)  
        print(str(method)+" ("+str(*args)+") [%.9f sec]"%(time.perf_counter()-startTime))
        return result
    return decorated_method

##──── GET MEMORY USAGE ───────────────────────────────────────────────────────────────────────────────────────────────────────
def get_mem_usage()->float:
    ''' Memory usage in MiB '''
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010

    class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
        _fields_ = [("cb", ctypes.c_ulong),
                    ("PageFaultCount", ctypes.c_ulong),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t)]
    
    ##──── LINUX & MACOS ─────────────
    try: 
        result = subprocess.check_output(['ps', '-p', str(os.getpid()), '-o', 'rss='])
        return float(int(result.strip()) / 1024)
    except:
        ##──── WINDOWS ─────────────
        try:
            pid = ctypes.windll.kernel32.GetCurrentProcessId()
            process_handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if ctypes.windll.psapi.GetProcessMemoryInfo(process_handle, ctypes.byref(counters), ctypes.sizeof(counters)):
                memory_usage = counters.WorkingSetSize
                return float((int(memory_usage) / 1024) / 1024)
        except:
            return 0.0
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

##──── IP MANIPULATION FUNCTIONS ─────────────────────────────────────────────────────────────────────────────────────────────────
# ipv4_to_int = lambda ipv4_address: struct.unpack('!I', socket.inet_aton(ipv4_address))[0]
def ipv4_to_int(ipv4_address):
    return struct.unpack('>L', socket.inet_aton(ipv4_address))[0]

# int_to_ipv4 = lambda iplong: socket.inet_ntoa(struct.pack('!I', iplong))
def int_to_ipv4(iplong):
    return socket.inet_ntoa(struct.pack('>L', iplong))

# ipv6_to_int = lambda ipv6_address: int.from_bytes(socket.inet_pton(socket.AF_INET6, ipv6_address), byteorder='big')
def ipv6_to_int(ipv6_address):
    return int.from_bytes(socket.inet_pton(socket.AF_INET6, ipv6_address), byteorder='big')

# int_to_ipv6 = lambda iplong: socket.inet_ntop(socket.AF_INET6, unhexlify(hex(iplong)[2:].zfill(32)))
def int_to_ipv6(iplong):
    return socket.inet_ntop(socket.AF_INET6, binascii.unhexlify(hex(iplong)[2:].zfill(32)))

##──── Number os possible IPs in a network range. (/0, /1 .. /8 .. /24 .. /30, /31, /32) ─────────────────────────────────────────
##──── Call the index of a list. Ex. numIPs[24] (is the number os IPs of a network range class C /24) ────────────────────────────
numIPsv4 = sorted([2**num for num in range(0,33)],reverse=True) # from 0 to 32
numIPsv4.append(0)
numIPsv6 = sorted([2**num for num in range(0,129)],reverse=True) # from 0 to 128
numIPsv6.append(0)
MAX_IPv4 = numIPsv4[0]
##──── numHosts is the numIPs - 2 ────────────────────────────────────────────────────────────────────────────────────────────────
numHostsv4 = sorted([(2**num)-2 for num in range(0,33)],reverse=True) # from 0 to 32
numHostsv6 = sorted([(2**num)-2 for num in range(0,129)],reverse=True) # from 0 to 128
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

##──── Join the splitted list ────────────────────────────────────────────────────────────────────────────────────────────────────
def join_list(list_of_lists):
    joined_list = []
    for sublist in list_of_lists:
        joined_list.extend(sublist)
    return joined_list

def split_list(lista, n):
    sliced_lists = []
    for i in range(0, len(lista), n):
        sliced_lists.append(lista[i:i + n])
    return sliced_lists
##───────────────────────────'─────────────────────────────────────────────────────────────────────────────────────────────────────

##──── Format a number like 123456789 into 123.456.789 ───────────────────────────────────────────────────────────────────────────
def format_num(number):
    return '{:,d}'.format(number).replace(',','.')

##──── Return bytes in human readable ────────────────────────────────────────────────────────────────────────────────────────────
def format_bytes(byte_size):
    """
    Format a byte size into a human-readable format (KiB, MiB, GiB, etc.).
    """
    suffix = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB']
    if byte_size == 0:
        return "0 B"
    i = 0
    while byte_size >= 1024 and i < len(suffix)-1:
        byte_size /= 1024.0
        i += 1
    return f"{byte_size:.2f} {suffix[i]}"

##──── GeoIP2Fast Exception Class ────────────────────────────────────────────────────────────────────────────────────────────────    
class GeoIPError(Exception):
    def __init__(self, message):
        self.message = message
    def __str__(self):
        return self.message
    def __repr__(self):
        return self.message
##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

##──── Object to store the information of city names ───────────────────────────────────────────────────────────────────────────
class CityDetail(object):
    """Object to store city information
    """
    def __init__(self, city_string="||||"):
        try:
            self.name, self.subdivision_code, self.subdivision_name, self.subdivision2_code, self.subdivision2_name = city_string.split("|")
        except:
            self.name, self.subdivision_code, self.subdivision_name, self.subdivision2_code, self.subdivision2_name = GEOIP_INTERNAL_ERROR_STRING,"","","",""
        self.latitude = None
        self.longitude = None
    def __init__121(self, city_string="||||||"):
        try:
            self.name, self.subdivision_code, self.subdivision_name, self.subdivision2_code, self.subdivision2_name, self.latitude, self.longitude = city_string.split("|")
        except:
            self.name, self.subdivision_code, self.subdivision_name, self.subdivision2_code, self.subdivision2_name, self.latitude, self.longitude = GEOIP_INTERNAL_ERROR_STRING,"","","","",0.0,0.0
    def to_dict(self):
        return {
            "name": self.name,
            "subdivision_code": self.subdivision_code,
            "subdivision_name": self.subdivision_name,
            "latitude": self.latitude,
            "longitude": self.longitude
        }
##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

##──── Object to store the information obtained by searching an IP address ───────────────────────────────────────────────────────
class GeoIPDetail(object):
    def __init__(self, ip, country_code="", country_name="", cidr="", is_private=False, asn_name="", asn_cidr="", elapsed_time=""):
        self.ip = ip
        self.country_code = country_code
        self.country_name = country_name
        self.cidr = cidr
        self.hostname = ""
        self.is_private = is_private
        self.asn_name = asn_name
        self.asn_cidr = asn_cidr
        self.elapsed_time = elapsed_time
    @property
    def city(self)->CityDetail:
        return CityDetail()
    def __str__(self):
        return f"{self.__dict__}"
    def __repr__(self):
        return f"{self.to_dict()}"    
    def get_hostname(self,dns_timeout=0.1):
        """Call this function to set the property 'hostname' with a socket.socket.gethostbyaddr(ipadr) dns lookup.

        Args:
            dns_timeout (float, optional): Defaults to 0.1.

        Returns:
            str: the hostname if success or an error message between < >
        """
        try:
            startTime = time.perf_counter()
            socket.setdefaulttimeout(dns_timeout)
            result = socket.gethostbyaddr(self.ip)[0]
            self.hostname = result if result != self.ip else ""
            self.elapsed_time_hostname = "%.9f sec"%(time.perf_counter()-startTime)
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
                "city":'',
                "cidr": self.cidr,
                "hostname": self.hostname,
                "asn_name": self.asn_name,
                "asn_cidr": self.asn_cidr,
                "is_private": self.is_private,
                "elapsed_time": self.elapsed_time
            }
            ##──── For aesthetic reasons, if it does not come from the derived class GeoIPDetailCity, delete the 'city' key ──────────────────
            ##──── otherwise keep the key so that it is in the position just below 'country_name' ────────────────────────────────────────────
            if not hasattr(self, 'city'):
                del d['city']
            ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            try:
                a = self.elapsed_time_hostname
                d['elapsed_time_hostname'] = self.elapsed_time_hostname
            except:
                pass
            return d
        except Exception as ERR:
            raise GeoIPError("Failed to_dict() %s"%(str(ERR)))
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
            raise GeoIPError("Failed pp_json() %s"%(str(ERR)))
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

##──── Object to store the information obtained by searching an IP address ───────────────────────────────────────────────────────
class GeoIPDetailCity(GeoIPDetail):
    """Extended version of GeoIPDetail with city information
    """
    def __init__(self, ip, country_code="", country_name="", city=None, cidr="", is_private=False, asn_name="", asn_cidr="", elapsed_time=""):
        super().__init__(ip, country_code, country_name, cidr, is_private, asn_name, asn_cidr, elapsed_time)
        self._city = city if city else CityDetail()
    @property
    def city(self):
        return self._city
    @city.setter
    def city(self, value):
        raise AttributeError("Cannot set 'city' attribute in GeoIPDetailCity")
    def to_dict(self):
        base_dict = super().to_dict()
        base_dict['city'] = self.city.to_dict() 
        return base_dict
    
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
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
        self.ipv6 = False
        self.city = False
        self.asn = False
        self.is_loaded = False
        
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
        
        if geoip2fast_data_file != "":
            try:
                # If it finds the specified file, perfect.
                if os.path.isfile(geoip2fast_data_file) == True:
                    self.data_file = geoip2fast_data_file
                else:
                    # If any file is specified without the path, try to locate it in the current directory or in the library directory
                    if geoip2fast_data_file.find("/") < 0:
                        databasePath = self.__locate_database_file(geoip2fast_data_file)
                        if databasePath is False:
                            raise GeoIPError("Unable to find GeoIP2Fast database file %s"%(os.path.basename(geoip2fast_data_file)))
                        else:
                            self.data_file = databasePath
                    else:
                        # If any file is specified with the path and is not found, raize an exception
                        raise GeoIPError("Check path of specified file and try again.")
            except Exception as ERR:
                raise GeoIPError("Unable to access the specified file %s. %s"%(geoip2fast_data_file,str(ERR)))
            
        self.__load_data(self.data_file, verbose)

    ##──── Function used to avoid "if verbose == True". The code is swaped at __init__ ───────────────────────────────────────────────
    def __print_verbose_empty(self,msg):return
    def __print_verbose_regular(self,msg):
        print(msg,flush=True)

    def _print_debug(self,msg):
        print("[DEBUG] "+msg,flush=True)
    def _print_verbose(self,msg):
        print(msg,flush=True)
    ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

    ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def __locate_database_file(self, filename):
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
    def __load_data(self, gzip_data_file:str, verbose=False)->bool:        
        global __DAT_VERSION__, source_info, totalNetworks,mainListNamesCountry,geoipCountryNamesDict,geoipCountryCodesList,\
               mainIndex,mainListNamesCountry,mainListFirstIP,mainListIDCountryCodes,mainListNetlength,\
               mainIndexASN,mainListNamesASN,mainListFirstIPASN,mainListIDASN,mainListNetlengthASN,\
               mainListNamesCity, mainListIDCity

        if self.is_loaded == True:
            return True   
        self._print_verbose = self.__print_verbose_regular if verbose == True else self.__print_verbose_empty
        
        startMem = get_mem_usage()
        startLoadData = time.perf_counter()
        ##──── Try to locate the database file in the directory of the application that called GeoIP2Fast() ─────────────────────────
        ##──── or in the directory of the GeoIP2Fast Library ────────────────────────────────────────────────────────────────────────
        try:
            if gzip_data_file == "":
                gzip_data_file = GEOIP2FAST_DAT_GZ_FILE
                try:
                    databasePath = self.__locate_database_file(os.path.basename(gzip_data_file))
                    if databasePath is False:
                        raise GeoIPError("(1) Unable to find GeoIP2Fast database file %s"%(os.path.basename(gzip_data_file)))
                    else:
                        self.data_file = databasePath
                except Exception as ERR:
                    raise GeoIPError("(2) Unable to find GeoIP2Fast database file %s %s"%(os.path.basename(gzip_data_file),str(ERR)))
        except Exception as ERR:
            raise GeoIPError("Failed at locate data file %s"%(str(ERR)))        
        
        ##──── Open the dat.gz file ──────────────────────────────────────────────────────────────────────────────────────────────────────
        try:
            try:
                if self.data_file.lower().endswith(".gz"):
                    inputFile = gzip.open(str(self.data_file),'rb')
                else:
                    inputFile = open(str(self.data_file),'rb')
                    self.data_file = self.data_file
            except Exception as ERR:
                raise GeoIPError(f"Unable to find {gzip_data_file} or {gzip_data_file} {str(ERR)}")
        except Exception as ERR:
            raise GeoIPError(f"Failed to 'load' GeoIP2Fast! the data file {gzip_data_file} appears to be invalid or does not exist! {str(ERR)}")
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────        
        
        ##──── Use -vvv on command line to see which dat.gz file is currently being used ─────────────────────────────────────────────────
        self._database_path = os.path.realpath(self.data_file)
        
        ##──── Load the dat.gz file into memory ──────────────────────────────────────────────────────────────────────────────────────────
        try:
            self.clear_cache()
            __DAT_VERSION__, source_info, totalNetworks, mainDatabase = pickle.load(inputFile)
          
            if __DAT_VERSION__ != 120 and __DAT_VERSION__ != 121:
                raise GeoIPError(f"Failed to pickle the data file {gzip_data_file}. Reason: Invalid version - requires 120/121, current {str(__DAT_VERSION__)}")
            
            self.source_info = source_info['info']
            self.country = source_info['country']
            self.city = source_info['city']
            self.asn = source_info['asn']

            ##──── ONLY COUNTRY ──────────────────────────────────────────────────────────────────────────────────────────────────────────────            
            if self.country == True and self.asn == False:
                mainIndex,mainListNamesCountry,mainListFirstIP,mainListIDCountryCodes,mainListNetlength = mainDatabase
            ##──── COUNTRY WITH ASN ──────────────────────────────────────────────────────────────────────────────────────────────────────────
            elif self.country == True and self.asn == True:
                mainIndex,mainIndexASN,mainListNamesCountry,mainListNamesASN,mainListFirstIP,\
                mainListFirstIPASN,mainListIDCountryCodes,mainListIDASN,mainListNetlength,mainListNetlengthASN = mainDatabase
            ##──── ONLY CITY ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            elif self.city == True and self.asn == False:
                if __DAT_VERSION__ == 120:
                    mainIndex,mainListNamesCountry,mainListNamesCity,mainListFirstIP,mainListIDCity,mainListNetlength = mainDatabase
                elif __DAT_VERSION__ == 121:
                    CityDetail.__init__.__code__ = CityDetail.__init__121.__code__
                    pass
            ##──── CITY WITH ASN ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
            elif self.city == True and self.asn == True:
                if __DAT_VERSION__ == 120:
                    mainIndex,mainIndexASN,mainListNamesCountry,mainListNamesCity,mainListNamesASN,\
                    mainListFirstIP,mainListFirstIPASN,mainListIDCity,mainListIDASN,mainListNetlength,mainListNetlengthASN = mainDatabase
                elif __DAT_VERSION__ == 121:
                    pass

            self.ipv6 = mainIndex[-1] > numIPsv4[0]
            geoipCountryNamesDict = {item.split(":")[0]:item.split(":")[1] for item in mainListNamesCountry}
            geoipCountryCodesList = list(geoipCountryNamesDict.keys())

            inputFile.close()
            del inputFile
        except Exception as ERR:
            raise GeoIPError(f"Failed to pickle the data file {gzip_data_file} {str(ERR)}")
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

        ##──── Warming-up ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        try:
            [self._main_index_lookup(iplong) for iplong in [694967295,2894967295,4294967295]]
        except Exception as ERR:
            raise GeoIPError("Failed at warming-up... exiting... %s"%(str(ERR)))
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        
        ##──── Load Time Info ──────────────────────────────────────────────────────────────────────────────────────────────────────────
        try:
            totalLoadTime = (time.perf_counter() - startLoadData)
            totalMemUsage = abs((get_mem_usage() - startMem))
            self._load_data_text = f"GeoIP2Fast v{__version__} is ready! {os.path.basename(gzip_data_file)} "+ \
                "loaded with %s networks in %.5f seconds and using %.2f MiB."%(format_num(totalNetworks),totalLoadTime,totalMemUsage)
            self._print_verbose(self._load_data_text)
        except Exception as ERR:
            raise GeoIPError("Failed at the end of load data %s"%(str(ERR)))
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        self.is_loaded = True
        return True

    def reload_data(self,verbose=None)->bool:
        """Reloads the currently used database.
        """
        if verbose is not None:
            self.verbose = verbose
        self.is_loaded = False
        return self.__load_data(gzip_data_file=self.data_file,verbose=self.verbose)
    
    @property
    def startup_line_text(self):
        """Returns the text of load_data() in case you want to know without set verbose=True
        
        Like: GeoIP2Fast v1.X.X is ready! geoip2fast.dat.gz loaded with XXXXXX networks in 0.0000 seconds and using YY.ZZ MiB
        """
        return self._load_data_text

    def get_database_path(self):
        """Returns the path of of the dat.gz file that is currently being used
        """
        return self._database_path

    def update_all(self,destination_path="",verbose=False):
        """
        Update ALL dat.gz files from repository.

        Usage:
            from geoip2fast import GeoIP2Fast

            G = GeoIP2Fast()
            
            result = G.update_all()
            
            print(result)
            
        - 'result' is a status code. Value 0 is OK. Any other value is not OK.

        - 'destination_path' is the directory path to save the downloaded files. 
          If empty, all files will be saved in the library path.
    
        - 'verbose' prints the download progress, otherwise will be a silent operation.
        
        Examples:

        - to download all files and save them in the current directory of your code.
        
        result = G.update_all(destination_path="./") 


        - to download all files and save them in the library path.
        
        result = G.update_all(destination_path="") 
        
        
        - to download all files and save them in the library path and print the download progress.
        
        result = G.update_all(destination_path="",verbose=True)
        
        """            
        geoipUpdate = UpdateGeoIP2Fast()
        return geoipUpdate.update_all(destination_path,verbose)

    def update_file(self,filename,destination="",verbose=False):
        """
        Update a specific dat.gz file from repository.

        Usage:
            from geoip2fast import GeoIP2Fast
            
            G = GeoIP2Fast(geoip2fast_data_file='geoip2fast-city-asn-ipv6.dat.gz',verbose=True)
            
            result = G.update_file(filename='geoip2fast-city-asn-ipv6.dat.gz')
            
            print(result)
            
            G.reload_data()
            
        - 'result' is a status code. Value 0 is OK. Any other value is not OK.

        - 'filename' is the name of dat.gz file. The allowed values are: 'geoip2fast.dat.gz' or 'geoip2fast-ipv6.dat.gz' or 'geoip2fast-asn.dat.gz' or 'geoip2fast-asn-ipv6.dat.gz' or 'geoip2fast-city.dat.gz' or 'geoip2fast-city-ipv6.dat.gz' or 'geoip2fast-city-asn.dat.gz' or 'geoip2fast-city-asn-ipv6.dat.gz'
    
        - 'destination' is the path to save the downloaded file. 
        
        - 'verbose' prints the download progress, otherwise will be a silent operation.
        
        Examples:
        
        - to download the file 'geoip2fast-asn-ipv6.dat.gz' and save it in the library path with the filename 'geoip2fast.dat.gz'

        result = G.update_file(filename='geoip2fast-asn-ipv6.dat.gz',destination='geoip2fast.dat.gz')


        - to download the file 'geoip2fast-asn-ipv6.dat.gz' and save it in current directory of your code with the filename 'geoip2fast.dat.gz'

        result = G.update_file(filename='geoip2fast-asn-ipv6.dat.gz',destination='./geoip2fast.dat.gz')

        
        - to download the file 'geoip2fast-asn-ipv6.dat.gz' and save it in the library path with the same filename

        result = G.update_file(filename='geoip2fast-asn-ipv6.dat.gz') 

        
        - to download the file 'geoip2fast-asn.dat.gz' and save it as "/tmp/geoip2fast-asn.dat.gz" and prints the download progress.

        result = G.update_file(filename='geoip2fast-asn.dat.gz',destination="/tmp/",verbose=True) 
        """    
        geoipUpdate = UpdateGeoIP2Fast()
        return geoipUpdate.update_file(filename,destination,verbose)

    def get_update_url(self)->str:
        """Returns the current URL for download the dat.gz files."""
        global GEOIP_UPDATE_DAT_URL
        return GEOIP_UPDATE_DAT_URL

    def set_update_url(self,new_url)->bool:
        """Change the URL for download of dat.gz files. You can use your own repository."""
        global GEOIP_UPDATE_DAT_URL
        try:
            parse_result = urllib.parse.urlparse(new_url)
            result = all([parse_result.scheme, parse_result.netloc])
            if result == True:
                GEOIP_UPDATE_DAT_URL = new_url
            return result
        except ValueError:
            return False            

    def get_ipv4_coverage(self)->float:
        """ Returns a percentage (float) compared with all possible IPsv4 """
        return self.calculate_coverage(False,False)

    def get_ipv6_coverage(self)->float:
        """ Returns a percentage (float) compared with all possible IPsv6 """
        global percentagev6
        percentage_v4 = self.calculate_coverage(False,False)
        return percentagev6
        
    # @functools.lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=False)
    def _main_index_lookup(self,iplong):
        try:
            matchRoot = bisect.bisect_right(mainIndex,iplong)-1
            matchChunk = bisect.bisect_right(mainListFirstIP[matchRoot],iplong)-1
            first_ip2int = mainListFirstIP[matchRoot][matchChunk]
            netlen = mainListNetlength[matchRoot][matchChunk]
            if iplong <= MAX_IPv4:
                last_ip2int = first_ip2int + numIPsv4[netlen]-1
            else:
                last_ip2int = first_ip2int + numIPsv6[netlen]-1
            return matchRoot, matchChunk, first_ip2int, last_ip2int, netlen
        except Exception as ERR:
            return GeoIPError("Failed at _main_index_lookup: %s"%(str(ERR)))
    
    # @functools.lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=False)
    def _country_lookup(self,match_root,match_chunk):
        try:
            country_code_index = mainListIDCountryCodes[match_root][match_chunk]
            country_code, country_name = mainListNamesCountry[country_code_index].split(":")
            is_private = country_code_index < 16
            country_code = self.error_code_private_networks if is_private else country_code
            return country_code, country_name, is_private
        except Exception as ERR:
            return GeoIPError("Failed at _country_lookup: %s"%(str(ERR)))

    # @functools.lru_cache(maxsize=300, typed=False)
    def _city_country_name_lookup(self,country_code):
        try:
            country_name = geoipCountryNamesDict[country_code]        
            country_code_index = geoipCountryCodesList.index(country_code)
            is_private = country_code_index < 16
            country_code = self.error_code_private_networks if is_private else country_code
            return country_code, country_name, is_private
        except Exception as ERR:
            return GeoIPError("Failed at _city_country_name_lookup: %s"%(str(ERR)))

    # @functools.lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=False)
    def _city_lookup(self,match_root,match_chunk):
        try:
            code = mainListIDCity[match_root][match_chunk]
            country_code, city_name = mainListNamesCity[code].split(":")
            country_code, country_name, is_private = self._city_country_name_lookup(country_code)            
            city_info = CityDetail(city_name)
            return country_code, country_name, city_info, is_private
        except Exception as ERR:
            return GeoIPError("Failed at _country_lookup: %s"%(str(ERR)))

    # @functools.lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=False)
    def _asn_lookup(self,iplong):
        if self.asn == False:
            return "", ""
        try:
            matchRoot = bisect.bisect_right(mainIndexASN,iplong)-1
            matchChunk = bisect.bisect_right(mainListFirstIPASN[matchRoot],iplong)-1
            first_ip2int = mainListFirstIPASN[matchRoot][matchChunk]
            asn_id = mainListIDASN[matchRoot][matchChunk]
            netlen = mainListNetlengthASN[matchRoot][matchChunk]
            if not self.ipv6:
                if iplong > ((first_ip2int + numIPsv4[netlen]) - 1):
                    return "", ""
            else:
                if iplong > ((first_ip2int + numIPsv6[netlen]) - 1):
                    return "", ""
            return mainListNamesASN[asn_id], self._int2ip(first_ip2int)+"/"+str(netlen)
        except Exception as ERR:
            return "", ""
    def test(self):
        
        print(json.dumps({item.split(":")[0]:item.split(":")[1] for item in mainListNamesCountry},sort_keys=False,ensure_ascii=False,separators=(",",":")))
        
    def _ip2int(self,ipaddr:str)->int:
        """
        Convert an IP Address into an integer number
        """    
        try:
            try:
                return int(struct.unpack('>L', socket.inet_aton(ipaddr))[0])
            except:
                return int.from_bytes(socket.inet_pton(socket.AF_INET6, ipaddr), byteorder='big')
        except Exception as ERR:
            raise GeoIPError("Failed at ip2int: %s"%(str(ERR)))

    def _int2ip(self,iplong:int)->str:
        """
        Convert an integer to IP Address
        """    
        try:
            if iplong < MAX_IPv4:
                return socket.inet_ntoa(struct.pack('>L', iplong))
            else:
                return socket.inet_ntop(socket.AF_INET6, binascii.unhexlify(hex(iplong)[2:].zfill(32)))
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
            raise GeoIPError("Unable to set a new value for GEOIP_ECCODE_PRIVATE_NETWORKS: %s"%(str(ERR)))
        
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
            raise GeoIPError("Unable to set a new value for GEOIP_ECCODE_NETWORK_NOT_FOUND: %s"%(str(ERR)))
        
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
        startTime = time.perf_counter()
        try:
            iplong = self._ip2int(ipaddr)
        except Exception as ERR:
            return GeoIPDetail(ipaddr,country_code=self.error_code_invalid_ip,\
                    country_name=GEOIP_INVALID_IP_STRING,elapsed_time='%.9f sec'%(time.perf_counter()-startTime))
        try:
            matchRoot, matchChunk, first_ip2int, last_ip2int, netlen = self._main_index_lookup(iplong)
            if iplong > last_ip2int:
                return GeoIPDetail(ip=ipaddr,country_code=self.error_code_network_not_found, \
                            country_name=GEOIP_NOT_FOUND_STRING,elapsed_time='%.9f sec'%(time.perf_counter()-startTime))            
            cidr = self._int2ip(first_ip2int)+"/"+str(netlen)
            asn_name, asn_cidr = self._asn_lookup(iplong)
            if self.country:
                country_code, country_name, is_private = self._country_lookup(matchRoot, matchChunk)
                ##──── SUCCESS! ────
                return GeoIPDetail(ipaddr,country_code,country_name,cidr,is_private,asn_name,asn_cidr,elapsed_time='%.9f sec'%((time.perf_counter()-startTime)))
            else:
                country_code, country_name, city_info, is_private = self._city_lookup(matchRoot, matchChunk)
                ##──── SUCCESS! ────
                return GeoIPDetailCity(ipaddr,country_code,country_name,city_info,cidr,is_private,asn_name,asn_cidr,elapsed_time='%.9f sec'%((time.perf_counter()-startTime)))
            ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        except Exception as ERR:
            return GeoIPDetail(ip=ipaddr,country_code=self.error_code_lookup_internal_error,\
                    country_name=GEOIP_INTERNAL_ERROR_STRING,elapsed_time='%.9f sec'%(time.perf_counter()-startTime))
            
    def clear_cache(self)->bool:
        """ 
        Clear the internal cache of lookup function
        
        Return: True or False
        """
        try:
            self._main_index_lookup.cache_clear()
            self._asn_lookup.cache_clear()
            self._country_lookup.cache_clear()
            self._city_country_name_lookup.cache_clear()
            self._city_lookup.cache_clear()
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
                "asn_lookup "+str(self._asn_lookup.cache_info()),\
                "country_lookup "+str(self._country_lookup.cache_info()),\
                "city_country_name_lookup "+str(self._city_country_name_lookup.cache_info()),\
                "city_lookup "+str(self._city_lookup.cache_info())
                )
        except Exception as ERR:
            print(str(ERR))
            return ("","","","","")
                    
    def generate_random_private_address(self,num_ips=1):
        """Generate an IP address from networks 10.0.0.0/8 or 172.16.0.0/12 or 192.168.0.0/16
        
           If only 1 IP is requested, returns a string, otherwise returns a list.
           
           If fails for some reason, raise an error.
        """
        return_list = []
        try:
            while (len(return_list) < num_ips):
                return_list.append(self._int2ip(random.choice([random.randint(167772160,184549375),random.randint(3232235520,3232301055),random.randint(2886729728,2887778303)])))
        except Exception as ERR:
            raise Exception(ERR)
        return return_list[0] if len(return_list) == 1 else return_list
                
    def generate_random_ipv4_address(self,num_ips=1):
        """Generate an IPv4 address from networks 1.0.0.0 until 223.255.255.255
        
           If only 1 IP is requested, returns a string, otherwise returns a list.
           
           If fails for some reason, raise an error.
        """
        return_list = []
        try:
            while (len(return_list) < num_ips):
                return_list.append(self._int2ip(random.randint(16777216,3758096383)))
        except Exception as ERR:
            raise Exception(ERR)
        return return_list[0] if len(return_list) == 1 else return_list
                
    def generate_random_ipv6_address(self,num_ips=1):
        """Generate an IPv6 address from some network that exists in GeoIP2Fast data file.
        
           If only 1 IP is requested, returns a string, otherwise returns a list.
           
           If a database without IPv6 was loaded, returns False.
           
           If fails for another reason, raise an error.
        """
        if self.ipv6 == False:
            return False
        return_list = []
        try:
            max_len_chunks = len(mainIndex)        
            matchRoot = bisect.bisect_right(mainIndex,numIPsv4[0])
            while (len(return_list) < num_ips):
                sortRoot = random.randint(matchRoot+1,max_len_chunks-1)
                sortChunk = random.randint(0,len(mainListFirstIP[sortRoot])-1)
                first_ip2int = mainListFirstIP[sortRoot][sortChunk]
                net_len = mainListNetlength[sortRoot][sortChunk]
                last_ip2int = (first_ip2int + numIPsv6[net_len])-1
                sorted_ipv6 = self._int2ip(random.randint(first_ip2int,last_ip2int))
                return_list.append(sorted_ipv6)
        except Exception as ERR:
            raise Exception(ERR)
        return return_list[0] if len(return_list) == 1 else return_list
        
        
    def self_test(self,with_city=False,max_ips=30,with_ipv6=False):
        """
            Do a self-test with some random IPs
        """              
        with_ipv6 = False if self.ipv6 == False else with_ipv6          
        MAX_IPS = max_ips
        ip_ljust_space = 21
        ip_string = "IPv4"
        ip_list = []
        ip_list.append("x"+self._int2ip(random.randint(16777216,3758096383)).replace(".",",")) # generates an invalid IP inserting the 'x' letter and changing dot by comma
        ip_list.append(self._int2ip(random.randint(16777216,3758096383))+"/32") # generates an invalid IP adding '/32' to the end. Is a valid CIDR but an invalid IP
        ip_list.append(self._int2ip(random.randint(397189376,397191423))) # generates a random IP between 23.172.161.0 and 23.172.168.255 to force a 'not found' response
        ip_list.append(self.generate_random_private_address()) # generates a random IP of a private network
        while len(ip_list) < max_ips:
            if with_ipv6 == True:
                ip_string = "IPv4 and IPv6"
                if random.randint(0,100) < 15: # 15% of IPv6
                    ip_list.append(self.generate_random_ipv6_address())
                else:
                    ip_list.append(self.generate_random_ipv4_address())
            else:
                ip_list.append(self.generate_random_ipv4_address())
        if with_ipv6 == True:
            ip_ljust_space = 39
        avgList, avgCacheList = [], []
        if with_city == True and self.city == False:
            with_city = False
        for IP in ip_list:
            geoip = self.lookup(IP)
            avgList.append(float(geoip.elapsed_time.split(" ")[0]))
            cachedResult = self.lookup(IP)
            avgCacheList.append(float(cachedResult.elapsed_time.split(" ")[0]))
            if self.city == True:
                endText = cachedResult.city.name if with_city == True else cachedResult.asn_name[:40]
            else:
                endText = cachedResult.asn_name[:40]
            print("> "+cWhite(IP.ljust(ip_ljust_space))+" "+str(geoip.country_code).ljust(3)+cWhite(str(geoip.country_name[:30]).ljust(30))+ \
                " ["+cWhite(geoip.elapsed_time)+"]  Cached > ["+cWhite(cachedResult.elapsed_time)+"] "+endText)

        print("")
        print("Self-test with %s randomic %s addresses."%(format_num(len(ip_list)),ip_string))
        # Discard the best and worst elapsed_time before calculate average
        print("\t- Average Lookup Time: %.9f seconds. "%(sum(sorted(avgList)[1:-1])/(len(ip_list)-2)))
        print("\t- Average Cached Lookups: %.9f seconds. "%(sum(sorted(avgCacheList)[1:-1])/(len(ip_list)-2)))
        print("")

    def random_test(self,max_ips=1000000,with_ipv6=False):
        """
            Do a self-test with 1.000.000 of randomic IPs
        """
        self.self_test(max_ips=max_ips,with_ipv6=with_ipv6)
    
    def __get_missing_subnets(self,initial_ipaddr,final_ipaddr)->list:
        try:
            return list(ipaddress.summarize_address_range(ipaddress.ip_address(initial_ipaddr), ipaddress.ip_address(final_ipaddr)))
        except Exception as ERR:
            raise Exception(ERR)

    def __format_large_number(self, number, decimal_places=2):
        suffixes = ["", "thousand", "million", "billion", "trillion", "quadrillion", "quintillion", "sextillion", "septillion", "octillion", "nonillion", "decillion", "undecillion", "duodecillion", "tredecillion", "quattuordecillion", "quindecillion"]
        for i in range(len(suffixes)):
            if abs(number) < 1000.0:
                return f"{round(number, decimal_places)} {suffixes[i].capitalize()}"
            number /= 1000.0
        return f"{round(number, decimal_places)} {suffixes[-1].capitalize()}"  # For very large numbers
            
    def show_missing_ips(self,verbose=False,with_ipv6=False):
        """
            Scan database for network ranges without geographic information. 
        """
        total_missing_ips = 0
        total_missing_ips_v6 = 0
        classDict = {}
        missingFirstRanges = []
        with_ipv6 = False if self.ipv6 == False else with_ipv6
        print("\nSearching for missing IPv4 addresses...\n")
        try:
            joinedFirstIPList = join_list(mainListFirstIP)
            joinedNetLengthList = join_list(mainListNetlength)
            startTime = time.perf_counter()
            for N in range(len(joinedFirstIPList)):
                first_iplong = joinedFirstIPList[N]
                if (first_iplong > numIPsv4[0]) and (with_ipv6 == False):
                    break
                if (first_iplong >= numIPsv4[0]) and (old_last_iplong == numIPsv4[0]) and (with_ipv6 == True):
                    first_ipv6 = first_iplong
                    old_last_iplong = first_iplong
                    print("\nSearching for missing IPv6 addresses...\n")
                    continue
                if first_iplong < numIPsv4[0]:
                    last_iplong = first_iplong + numIPsv4[joinedNetLengthList[N]] 
                elif with_ipv6 == True:
                    last_iplong = first_iplong + numIPsv6[joinedNetLengthList[N]] 
                if first_iplong == 0:
                    old_last_iplong = last_iplong
                    continue
                missing_ips = first_iplong - old_last_iplong
                if missing_ips > 0:
                    # print(old_last_iplong,first_iplong)
                    missingRanges = self.__get_missing_subnets(self._int2ip(old_last_iplong),self._int2ip(first_iplong-1))
                    for cidr in missingRanges:
                        if first_iplong <= MAX_IPv4:
                            if verbose == True:
                                if classDict.get(str(cidr).split(".")[0],"X") == "X":
                                    classDict[str(cidr).split(".")[0]] = 0
                                classDict[str(cidr).split(".")[0]] += numIPsv4[cidr.prefixlen]
                            print(f"> From {cWhite(str(cidr.network_address).ljust(16))} to {cWhite(str(cidr.broadcast_address).ljust(16))} > Network: {cWhite(str(cidr).ljust(19))} > Missing IPs: {cWhite(numIPsv4[cidr.prefixlen])}")
                            total_missing_ips += numIPsv4[cidr.prefixlen]
                        else:
                            print(f"> Network: {cWhite(str(cidr).ljust(30))} > Missing IPs: {cWhite(self.__format_large_number(numIPsv6[cidr.prefixlen]))}")
                            total_missing_ips_v6 += numIPsv6[cidr.prefixlen]
                old_last_iplong = last_iplong
            if with_ipv6 == True:   # the last IPv6 range
                first_iplong = old_last_iplong+1
                total_missing_ips_v6 += first_ipv6 - 1 # sum from 0 to the first IPv6 found in database
                # go from the last ipv6 range in database to the last ipv6 possible (ffff::/128)
                missingRanges = self.__get_missing_subnets(self._int2ip(old_last_iplong),self._int2ip(numIPsv6[0]-1))
                for cidr in missingRanges:
                    print(f"> Network: {cWhite(str(cidr).ljust(30))} > Missing IPs: {cWhite(self.__format_large_number(numIPsv6[cidr.prefixlen]))}")
                    total_missing_ips_v6 += numIPsv6[cidr.prefixlen]
            if verbose == True:
                print("")
                print("  > Missing IPv4 by network class:\n")
                classDict = dict(sorted(classDict.items(),key=lambda x:int(x[0]), reverse=False))
                classDictRev = dict(sorted(classDict.items(),key=lambda x:int(x[1]), reverse=True))
                index = 0
                for k,v in classDictRev.items():
                    print(f"    - Class {k}.0.0.0/8".ljust(25,'.')+": "+f"{cWhite(format_num(v).ljust(20))} Class {str(list(classDict.keys())[index]+'.0.0.0/8').ljust(13,'.')}: {cWhite(format_num(list(classDict.values())[index]))}")
                    index += 1
            print("")
            percentage = (total_missing_ips * 100) / (numIPsv4[0]) # don´t count the network 0.0.0.0/8
            print(f">>> IPv4 addresses without geo information: {cYellow(format_num(total_missing_ips))} (%.2f%% of all IPv4) [%.5f sec]"%(percentage,time.perf_counter()-startTime))   
            if with_ipv6 == True:
                percentage_v6 = (total_missing_ips_v6 * 100) / (numIPsv6[0])
                print(f">>> IPv6 addresses without geo information: {cYellow(self.__format_large_number(total_missing_ips_v6))} (%.2f%% of all IPv6) [%.5f sec]"%(percentage_v6,time.perf_counter()-startTime))   

        except Exception as ERR:
            raise GeoIPError("Failed to show missing IPs information. %s"%(str(ERR)))
        
    def calculate_coverage(self,print_result=False,verbose=False,with_ipv6=False)->float:
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
            float: Returns a percentage compared with all possible IPsv4
        """
        global percentagev6
        with_ipv6 = False if self.ipv6 == False else with_ipv6
        try:
            joinedFirstIPList = join_list(mainListFirstIP)
            joinedNetLengthList = join_list(mainListNetlength)
            startTime = time.perf_counter()
            ipCounterv4, ipCounterv6 = 0, 0
            totalNetworksv4, totalNetworksv6  = 0, 0
            index = 0
            num_ipsv4, num_ipsv6 = 0, 0
            for item in joinedNetLengthList:
                if (verbose and print_result == True):
                    startTimeCIDR = time.perf_counter()
                    IP = str(self._int2ip(joinedFirstIPList[index]))
                    CIDR = IP + "/" + str(item)
                    result = self.lookup(IP)
                if joinedFirstIPList[index] < MAX_IPv4-1:
                    num_ipsv4 = numIPsv4[item]
                    ipCounterv4 += num_ipsv4
                    totalNetworksv4 += 1
                    num_ips_string = format_num(num_ipsv4).ljust(10)
                    if (verbose and print_result == True):
                        print(f"- Network: {cWhite(CIDR.ljust(19))} IPs: {cWhite(num_ips_string)} {result.country_code} {cWhite(result.country_name.ljust(35))} {'%.9f sec'%(time.perf_counter()-startTimeCIDR)}")
                else:
                    num_ipsv6 = numIPsv6[item]
                    ipCounterv6 += num_ipsv6
                    totalNetworksv6 += 1
                    num_ips_string = self.__format_large_number(num_ipsv6).ljust(20)
                    if (with_ipv6 == True and verbose and print_result):
                        print(f"- Network: {cWhite(CIDR.ljust(19))} IPs: {cWhite(num_ips_string)} {result.country_code} {cWhite(result.country_name.ljust(35))} {'%.9f sec'%(time.perf_counter()-startTimeCIDR)}")
                index += 1                        
            percentagev4 = (ipCounterv4 * 100) / numIPsv4[0]
            percentagev6 = (ipCounterv6 * 100) / numIPsv6[0]                
            endTime = time.perf_counter()
            if print_result == True:
                if verbose: print("")
                print(f"Current IPv4 coverage: %s ({format_num(ipCounterv4)} IPv4 in %s networks) [%.5f sec]"%(cYellow(str('%.2f%%'%(percentagev4)).rjust(7)),format_num(totalNetworksv4),(endTime-startTime)))
                if with_ipv6:
                    print(f"Current IPv6 coverage: %s ({format_num(ipCounterv6)} IPv6 in %s networks) [%.5f sec]"%(cYellow(str('%.2f%%'%(percentagev6)).rjust(7)),format_num(totalNetworksv6),(endTime-startTime)))
            return percentagev4
        except Exception as ERR:
            raise GeoIPError("Failed to calculate total IP coverage. %s"%(str(ERR)))
        

    def calculate_speed(self,print_result=False,max_ips=1000000)->float:
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
            MAX_IPS = max_ips
            self.clear_cache()
            startTime = time.perf_counter()
            # COULD BE A LITTLE BIT FASTER IF YOU GENERATE A LIST WITH 1.000.000 IPs BEFORE LOOKUP.
            # BUT LET´S KEEP LIKE THIS TO SPEND SOME MILLISECONDS TO GET CLOSER A REAL SITUATION OF USE            
            for NUM in range(MAX_IPS):
                IP = self._int2ip(random.randint(16777216,3758096383)) # from 1.0.0.0 to 223.255.255.255
                ipinfo = self.lookup(IP)
                XXXX = ipinfo.country_code # SIMULATE THE USE OF THE RETURNED VALUE
            total_time_spent = time.perf_counter() - startTime
            current_lookups_per_second = MAX_IPS / total_time_spent
            if print_result == True:
                print("Current speed: %.2f lookups per second (%s IPs with an average of %.9f seconds per lookup) [%.5f sec]"%(current_lookups_per_second,format_num(MAX_IPS),total_time_spent / MAX_IPS,time.perf_counter()-startTime))

            # method 02 - Use the sum of all elapsed time returned by each lookup instead the time spent by the whole function
            # self.clear_cache()   
            # startTime = time.perf_counter()
            # elapsed_time_lookup_list = []
            # for NUM in range(MAX_IPS):
            #     IP = self._int2ip(random.randint(16777216,3758096383)) # from 1.0.0.0 to 223.255.255.255
            #     ipinfo = self.lookup(IP)
            #     XXXX = ipinfo.country_code # SIMULATE THE USE OF THE RETURNED VALUE
            #     elapsed_time_lookup_list.append(float(ipinfo.elapsed_time.split()[0]))
            # current_lookups_per_second = len(elapsed_time_lookup_list) / sum(elapsed_time_lookup_list)
            # print("Current speed: %.2f lookups per second (%s IPs with an average of %.9f seconds per lookup) [%.5f sec]"%(current_lookups_per_second,format_num(MAX_IPS),sum(elapsed_time_lookup_list) / len(elapsed_time_lookup_list),time.perf_counter()-startTime))
            return current_lookups_per_second
        except Exception as ERR:
            raise GeoIPError("Failed to calculate current speed. %s"%(str(ERR)))
            

    def get_database_info(self):
        """Returns detailed information about the data file currently in use
        """
        def get_list_size(listname):
            try:
                return (len(listname[0])*(len(mainIndex)-1))+len(listname[-1])
            except:
                return 0 
        def get_list_ipaddress_size(listname):
            try:
                count_ipv4 = sum(len([num for num in sublist if num <= numIPsv4[0]]) for sublist in listname)
                count_ipv6 = sum(len([num for num in sublist if num > numIPsv4[0]]) for sublist in listname)
                return count_ipv4,count_ipv6
            except:
                return 0, 0
        def get_file_size_uncompressed(data_file_full_path):
            try:
                with gzip.open(data_file_full_path,'rb') as inputFile:
                    uncompressed_data = inputFile.read()
                    file_size = len(uncompressed_data)
                    del uncompressed_data
                    del inputFile
                    return file_size
            except Exception as ERR:
                print(ERR)
                return 0
        
        database_content = "Country" if self.country else "Country + City"
        database_content += " + ASN" if self.asn else ""
        database_content += " with IPv4 and IPv6" if self.ipv6 else " with IPv4 only"
        
        return_data = { 'database_content':database_content,
                        'database_fullpath':self.get_database_path(),
                        'file_size':os.path.getsize(self.get_database_path()),
                        'uncompressed_file_size':get_file_size_uncompressed(self.get_database_path()),
                        'source_info':self.source_info,
                        'dat_version':__DAT_VERSION__,
                       }
        if self.country:
            ipv4,ipv6 = get_list_ipaddress_size(mainListFirstIP)
            return_data.update({'country':{
                            "main_index_size":len(mainIndex),
                            "first_ip_list_size":get_list_size(mainListFirstIP),
                            "country_code_id_list_size":get_list_size(mainListIDCountryCodes),
                            "netlength_list_size":get_list_size(mainListNetlength),
                            "country_names":len(mainListNamesCountry),
                            "ipv4_networks":ipv4,
                            "ipv6_networks":ipv6,
                            "number_of_chunks":(len(mainIndex)),
                            "chunk_size":(len(mainListFirstIP[0])),                            
            }})
        if self.city:
            ipv4,ipv6 = get_list_ipaddress_size(mainListFirstIP)
            return_data.update({'city':{
                            "main_index_size":len(mainIndex),
                            "first_ip_list_size":get_list_size(mainListFirstIP),
                            "city_names_id_list_size":get_list_size(mainListIDCity),
                            "netlength_list_size":get_list_size(mainListNetlength),
                            "country_names":len(mainListNamesCountry),
                            "city_names":len(mainListNamesCity),
                            "ipv4_networks":ipv4,
                            "ipv6_networks":ipv6,                            
                            "number_of_chunks":(len(mainIndex)),
                            "chunk_size":(len(mainListFirstIP[0])),                            
            }})
        if self.asn:
            ipv4,ipv6 = get_list_ipaddress_size(mainListFirstIPASN)
            return_data.update({'asn':{
                            "main_index_size":len(mainIndexASN),
                            "first_ip_list_size":get_list_size(mainListFirstIPASN),
                            "netlength_list_size":get_list_size(mainListNetlengthASN),
                            "asn_names":len(mainListNamesASN),
                            "ipv4_networks":ipv4,
                            "ipv6_networks":ipv6,                            
                            "number_of_chunks":(len(mainIndexASN)),
                            "chunk_size":(len(mainListFirstIPASN[0])),                            
            }})
        return return_data


##########################################################################################
          
##     ## ########  ########     ###    ######## ########    ########     ###    ########
##     ## ##     ## ##     ##   ## ##      ##    ##          ##     ##   ## ##      ##
##     ## ##     ## ##     ##  ##   ##     ##    ##          ##     ##  ##   ##     ##
##     ## ########  ##     ## ##     ##    ##    ######      ##     ## ##     ##    ##
##     ## ##        ##     ## #########    ##    ##          ##     ## #########    ##
##     ## ##        ##     ## ##     ##    ##    ##          ##     ## ##     ##    ##
 #######  ##        ########  ##     ##    ##    ########    ########  ##     ##    ##

##########################################################################################

class UpdateGeoIP2Fast(object):
    def __init__(self):
        global GEOIP_UPDATE_DAT_URL
        ##──── Adjust the update URL to ensure that ends with a slash ─────────────────────────────────────────────────────────────
        if GEOIP_UPDATE_DAT_URL[-1] != "/":
            GEOIP_UPDATE_DAT_URL += "/"
        ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    ##──── Function used to avoid "if verbose == True". The code is swaped at __init__ ───────────────────────────────────────────────
    def _print_verbose(self,msg="",end="\n",flush=False):...
    def _print_verbose_empty(self,msg="",end="\n",flush=False):...
    def _print_verbose_regular(self,msg="",end="\n",flush=False):
        print(str(msg),end=str(end),flush=flush)

    def update_error(self,error_message=""):
        self._print_verbose(cRed(error_message))
        return {'error':error_message}
                    
    ##──── Download file following redirects with max_retries ────────────────────────────────────────────────────────────────────────
    ##──── This is a test for a future version that will update dat files automatically ──────────────────────────────────────────────
    def __download_file_from_url(self, url, destination_path="", destination_filename="", user_agent=f"{__appid__} v{__version__}", max_redirects=3, max_retries=3, timeout=5, verbose=False):
        self._print_verbose = self._print_verbose_empty if verbose == False else self._print_verbose_regular
        redirects = 0
        # Get the remote filename
        try:
            file_name = url.split("/")[-1]
        except Exception as ERR:
            return self.update_error(f"Cannot split the URL {url} - {str(ERR)}")
        
        for retry in range(max_retries+1):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': user_agent})
                with urllib.request.urlopen(req,timeout=timeout) as response:
                    if response.getcode() == 302:
                        # Handle redirection
                        if redirects < max_redirects:
                            url = response.headers['Location']
                            redirects += 1
                            self._print_verbose(f"Redirecting... ({redirects}/{max_redirects})")
                            continue
                        else:
                            return self.update_error("Exceeded maximum redirects.")
                    # check if is text or binary
                    content_type = response.headers.get('Content-Type', '').lower()
                    is_text = content_type.startswith('text/')
                    is_binary = content_type.startswith('application/')
                    if is_text:
                        return self.update_error("- Content is text. Aborting download.")
                    elif not is_binary:
                        self._print_verbose(f"- Unknown content type: {content_type}. Proceeding with download.")
                    
                    # Get file last modified date
                    last_modified_date = response.headers['Last-Modified'] if 'Last-Modified' in response.headers else None
                    self._print_verbose(f"- Last Modified Date: {last_modified_date}")  
                    
                    # Initialize progress variables
                    total_size = int(response.headers.get('Content-Length', 0))
                    downloaded_size = 0
                    chunk_size = 4096
                    
                    # Start downloading
                    startTime = time.perf_counter()
                    if destination_path == "":
                        destination_path = os.path.dirname(__file__)
                    if destination_filename == "" or destination_filename == "." or destination_filename.find(".") < 0:
                        destination_filename = file_name
                    try:
                        with open(os.path.join(destination_path,destination_filename), 'wb') as output_file:
                            self._print_verbose(f"- Downloading {file_name}... 0%", end="", flush=True)
                            while True:
                                chunk = response.read(chunk_size)
                                if not chunk:
                                    break
                                output_file.write(chunk)
                                downloaded_size += len(chunk)
                                percent = (downloaded_size / total_size) * 100 if total_size > 0 else 0
                                bytes_per_sec = downloaded_size / (time.perf_counter()-startTime)
                                elapsed_time = time.perf_counter()-startTime
                                self._print_verbose(f"\r- Downloading {file_name}... {percent:.2f}% of {format_bytes(total_size)} [{format_bytes(bytes_per_sec)}/s] [{(elapsed_time):.3f} sec]", end="", flush=True)
                    except Exception as ERR:
                        return self.update_error(f"- Error saving file {str(ERR)}")
                    self._print_verbose("")                                
                    self._print_verbose(f"- File saved to: {os.path.join(destination_path,destination_filename)}")
                    return {'error':None,
                            'url':url,
                            'remote_filename':file_name,
                            'last_modified_date':last_modified_date,
                            'file_size':total_size,
                            'file_destination':os.path.join(destination_path,destination_filename),
                            'average_download_speed':format_bytes(total_size)+"/sec",
                            'elapsed_time':'%.6f'%(elapsed_time),
                            }
            except urllib.error.URLError as ERR:
                error_message = f"- Error downloading file: {str(ERR)} - {url}"
                self._print_verbose(cRed(error_message))
                if retry < max_retries:
                    if max_retries > 0:
                        self._print_verbose(f"Retrying... ({retry + 1}/{max_retries})")
                        time.sleep(1)
                        continue
                else:
                    if max_retries > 0:
                        error_message = "Exceeded maximum retries."
                return self.update_error(error_message)

    ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def update_all(self,destination_path="",verbose=False):
        """
        Update ALL dat.gz files from repository.

        Usage:
            from geoip2fast import UpdateGeoIP2Fast

            U = UpdateGeoIP2Fast()
            
            result = U.update_all()
            
            print(result)
            
        - 'result' is a status code. Value 0 is OK. Any other value is not OK.

        - 'destination_path' is the directory path to save the downloaded files. 
          If empty, all files will be saved in the library path.
    
        - 'verbose' prints the download progress, otherwise will be a silent operation.
        
        Examples:

        - to download all files and save them in the current directory of your code.
        
        result = U.update_all(destination_path="./") 


        - to download all files and save them in the library path.
        
        result = U.update_all(destination_path="") 
        
        
        - to download all files and save them in the library path and print the download progress.
        
        result = U.update_all(destination_path="",verbose=True)
        
        """            
        global GEOIP_POSSIBLE_FILENAMES, GEOIP_UPDATE_DAT_URL
        self._print_verbose = self._print_verbose_empty if verbose == False else self._print_verbose_regular
        return_info = []
        
        ##──── Sanitize the destination_path variable ────────────────────────────────────────────────────────────────────────────────────
        if destination_path == "":
            destination_path = os.path.dirname(__file__)
        if (destination_path[-1] == ".") and (len(destination_path) > 1):
            destination_path = destination_path[:-1]
        if destination_path[-1] != "/":
            destination_path += "/"
        
        if not os.path.isdir(destination_path):
            return self.update_error(f"- Error: invalid directory: {destination_path}")

        for file in GEOIP_POSSIBLE_FILENAMES:
            try:
                url = f"{GEOIP_UPDATE_DAT_URL}{file}"
                self._print_verbose(f"- Opening URL {url}")
                value = self.__download_file_from_url(url=url,destination_path=destination_path,max_retries=0,verbose=verbose)
                return_info.append(value)
                if GEOIP_POSSIBLE_FILENAMES.index(file) != len(GEOIP_POSSIBLE_FILENAMES)-1:
                    self._print_verbose(f"")
            except Exception as ERR:
                return_info.append(self.update_error(f"ERROR downloading file {file} - {str(ERR)}"))
        return return_info
    
    def update_file(self,filename,destination="",verbose=False):
        """
        Update a specific dat.gz file from repository.

        Usage:
            from geoip2fast import UpdateGeoIP2Fast
            
            U = UpdateGeoIP2Fast(geoip2fast_data_file='geoip2fast-asn-ipv6.dat.gz',verbose=True)
            
            result = U.update_file(filename='geoip2fast-asn-ipv6.dat.gz')
            
            print(result)
            
        - 'result' is a status code. Value 0 is OK. Any other value is not OK.

        - 'filename' is the name of dat.gz file. The allowed values are: 'geoip2fast.dat.gz' or 'geoip2fast-ipv6.dat.gz' or 'geoip2fast-asn.dat.gz' or 'geoip2fast-asn-ipv6.dat.gz'
    
        - 'destination' is the path to save the downloaded file. 
        
        - 'verbose' prints the download progress, otherwise will be a silent operation.
        
        Examples:
        
        - to download the file 'geoip2fast-asn-ipv6.dat.gz' and save it in the library path with the filename 'geoip2fast.dat.gz'

        result = U.update_file(filename='geoip2fast-asn-ipv6.dat.gz',destination='geoip2fast.dat.gz')


        - to download the file 'geoip2fast-asn-ipv6.dat.gz' and save it in current directory of your code with the filename 'geoip2fast.dat.gz'

        result = U.update_file(filename='geoip2fast-asn-ipv6.dat.gz',destination='./geoip2fast.dat.gz')

        
        - to download the file 'geoip2fast-asn-ipv6.dat.gz' and save it in the library path with the same filename

        result = U.update_file(filename='geoip2fast-asn-ipv6.dat.gz') 

        
        - to download the file 'geoip2fast-asn.dat.gz' and save it as "/tmp/geoip2fast-asn.dat.gz" and prints the download progress.

        result = U.update_file(filename='geoip2fast-asn.dat.gz',destination="/tmp/",verbose=True) 
        """            
        global GEOIP_UPDATE_DAT_URL
        self._print_verbose = self._print_verbose_empty if verbose == False else self._print_verbose_regular
        print(filename)
        if filename not in GEOIP_POSSIBLE_FILENAMES:
            return self.update_error(f'Invalid filename. Choose one of {str(GEOIP_POSSIBLE_FILENAMES)[1:-1].replace(", ",",")}')

        ##──── Prepare the dest_dir and dest_filename variables ──────────────────────────────────────────────────────────────────────────
        if destination == "":
            dest_dir, dest_filename = os.path.split(os.path.abspath(__file__))
            dest_filename = filename
        else:
            try:
                if (destination.lower().find(".dat.gz") < 0) and (destination[-1] != "/"):
                    destination += "/"
                dest_dir, dest_filename = os.path.split(destination)
                if dest_dir == "":
                    dest_dir = os.path.dirname(__file__)                
                if dest_filename == "":
                    dest_filename = filename
            except Exception as ERR:
                return self.update_error(str(ERR))
        dest_dir, dest_filename = os.path.split(os.path.abspath(os.path.join(dest_dir,dest_filename)))
        
        ##──── This check prevents your code from being overwritten by a downloaded file. ────────────────────────────────────────────────
        ##──── Filename extensions other than .dat.gz are not accepted ───────────────────────────────────────────────────────────────────
        if dest_filename.lower().endswith(".dat.gz") == False:
            return self.update_error(f'The destination file extension is invalid. It must end with .dat.gz.')

        if not os.path.isdir(dest_dir):
            return self.update_error(f"- Error: Not a valid directory: '{dest_dir}'")

        destination = os.path.abspath(os.path.join(dest_dir,dest_filename))
                
        url = f"{GEOIP_UPDATE_DAT_URL}{filename}"
        self._print_verbose(f"- Opening URL {url}")
        return self.__download_file_from_url(url=url,destination_path=dest_dir,destination_filename=dest_filename,max_retries=0,verbose=verbose)

##──── A SIMPLE AND FAST CLI ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
def main_function():
    ncmd = len(sys.argv)
    verbose_mode = False
    resolve_hostname = False
    with_ipv6 = False
    geoip2fast_datafile = ""    
    if '-v' in sys.argv: 
        verbose_mode = True
        sys.argv.pop(sys.argv.index('-v'))
        ncmd -= 1
    if '-d' in sys.argv: 
        resolve_hostname = True
        sys.argv.pop(sys.argv.index('-d'))
        ncmd -= 1
    if '--with-ipv6' in sys.argv: 
        with_ipv6 = True
        sys.argv.pop(sys.argv.index('--with-ipv6'))
        ncmd -= 1
    if '-vvv' in sys.argv:
        geoip = GeoIP2Fast(geoip2fast_data_file=geoip2fast_datafile,verbose=True)
        geoip.test()
        sys.exit(0)
        # print(f"Using datafila: {os.path.realpath(geoip.get_database_path())}")
        # sys.exit(0)
    if ('--info' in sys.argv) or ('-i' in sys.argv):
        geoip = GeoIP2Fast(geoip2fast_data_file=geoip2fast_datafile,verbose=verbose_mode)
        print(json.dumps(geoip.get_database_info(),indent=3,sort_keys=False,ensure_ascii=False))
        sys.exit(0)

    ##──── Downloads all data files available and saves them to the specified path or filename supplied in --dest parameter ─────────────────────
    if '--update-all' in sys.argv: 
        if '--dest' in sys.argv:
            index = sys.argv.index('--dest')
            try:
                destination_param = sys.argv[index+1]
            except:
                if verbose_mode:print(cRed("Error in --dest parameter."))
                sys.exit(1) 
        else:
            destination_param = ""

        if verbose_mode:print("")
        U = UpdateGeoIP2Fast()
        update_result = U.update_all(destination_path=destination_param,verbose=verbose_mode)
        if verbose_mode:print("")
        
        if isinstance(update_result,dict):
            sys.exit(1)
        else:
            errors_result = [item for item in update_result if item['error'] is not None]
            sys.exit(len(errors_result))
    ##──── Downloads a specific data file and saves them to the specified path or filename supplied in --dest parameter ─────────────────────
    if '--update-file' in sys.argv: 
        index = sys.argv.index('--update-file')
        try:
            download_filename_param = sys.argv[index+1]
        except:
            if verbose_mode:print(cRed(F'Error in --update-file parameter. Choose one of {str(GEOIP_POSSIBLE_FILENAMES)[1:-1].replace(", ",",")}'))
            sys.exit(1) 
            
        if '--dest' in sys.argv:
            index = sys.argv.index('--dest')
            try:
                destination_param = sys.argv[index+1]
            except:
                if verbose_mode:print(cRed("Error in --dest parameter."))
                sys.exit(1)
        else:
            destination_param = ""

        if verbose_mode:print("")
        U = UpdateGeoIP2Fast()
        update_result = U.update_file(filename=download_filename_param,destination=destination_param,verbose=verbose_mode)
        if verbose_mode:print("")

        if update_result.get('error',0) is None:
            sys.exit(0)
        else:
            sys.exit(1)
    ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    for arg in sys.argv: # search in command line arguments if a geoip2fast dat.gz filename is specified
        match = re.match(r'.*geoip2fast.*\.dat\.gz',arg)
        if (match):
            geoip2fast_datafile = match.group(0)
            sys.argv.pop(sys.argv.index(geoip2fast_datafile))
            break
        else:
            match = re.match(r'.*geoip2fast.*\.dat',arg)
            if (match):
                geoip2fast_datafile = match.group(0)
                sys.argv.pop(sys.argv.index(geoip2fast_datafile))
                break
    ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    if '--speed-test' in sys.argv or '--speedtest' in sys.argv:
        geoip = GeoIP2Fast(geoip2fast_data_file=geoip2fast_datafile,verbose=True)
        print("\nCalculating current speed... wait a few seconds please...\n")
        geoip.calculate_speed(True)
        print("")
        sys.exit(0)
    if '--random-test' in sys.argv or '--randomtest' in sys.argv:
        geoip = GeoIP2Fast(geoip2fast_data_file=geoip2fast_datafile,verbose=True)
        num_ips = next((re.match('^[0-9]*$',item).group(0) for item in sys.argv if re.match('^[0-9]*$',item)),1000000)
        print("")
        geoip.random_test(max_ips=int(num_ips),with_ipv6=with_ipv6)
        print("")
        sys.exit(0)
    if '--missing-ips' in sys.argv or '--missingips' in sys.argv:
        geoip = GeoIP2Fast(geoip2fast_data_file=geoip2fast_datafile,verbose=True)
        geoip.show_missing_ips(verbose=verbose_mode,with_ipv6=with_ipv6)
        print("")
        sys.exit(0)
    if '--self-test-city' in sys.argv or '--selftestcity' in sys.argv:
        geoip = GeoIP2Fast(geoip2fast_data_file=geoip2fast_datafile,verbose=True)
        num_ips = next((re.match('^[0-9]*$',item).group(0) for item in sys.argv if re.match('^[0-9]*$',item)),30)
        print("\nStarting a self-test...\n")
        geoip.self_test(with_city=True,max_ips=int(num_ips),with_ipv6=with_ipv6)
        print("")
        sys.exit(0)
    if '--self-test' in sys.argv or '--selftest' in sys.argv:
        geoip = GeoIP2Fast(geoip2fast_data_file=geoip2fast_datafile,verbose=True)
        num_ips = next((re.match('^[0-9]*$',item).group(0) for item in sys.argv if re.match('^[0-9]*$',item)),30)
        print("\nStarting a self-test...\n")
        geoip.self_test(max_ips=int(num_ips),with_ipv6=with_ipv6)
        print("")
        sys.exit(0)
    if '--coverage' in sys.argv: 
        geoip = GeoIP2Fast(geoip2fast_data_file=geoip2fast_datafile,verbose=True)
        print("\nUse the parameter '-v' to see all networks included in your %s file.\n"%(geoip.get_database_path()))
        if verbose_mode == False:
            with_ipv6 = True
        geoip.calculate_coverage(True,verbose=verbose_mode,with_ipv6=with_ipv6)
        print("")
        sys.exit(0)
    ##──── Use -vvv on command line to see which dat.gz file is currently being used ─────────────────────────────────────────────────
    # self._database_path = self.data_file
        
    if (len(sys.argv) > 1) and (sys.argv[1] is not None) and ('-h' not in sys.argv) and ('--help' not in sys.argv):
        a_list = sys.argv[1].replace(" ","").split(",")
        if len(a_list) > 0:
            geoip = GeoIP2Fast(geoip2fast_data_file=geoip2fast_datafile,verbose=verbose_mode)
            for IP in a_list:
                result = geoip.lookup(str(IP))
                if resolve_hostname == True: result.get_hostname()
                result.pp_json(print_result=True)
        sys.exit(0)
    else:
        print(f"GeoIP2Fast v{__version__} Usage: {os.path.basename(__file__)} [-h] [-v] [-d] [-i] [data_filename_to_be_used] <ip_address_1>,<ip_address_2>,<ip_address_N>,...")
        if '-h' in sys.argv or '--help' in sys.argv:
            print(f"""
Tests parameters:
  --speed-test        Do a speed test with 1 million on randomic IP addresses.                                               
  
  --self-test [num_ips] [--with-ipv6]
                      Starts a self-test with some randomic IP addresses.
                      
  --self-test-city [num_ips] [--with-ipv6]
                      Starts a self-test with some randomic IP addresses and with city names support.
                      
  --random-test [num_ips] [--with-ipv6]
                      Start a test with 1.000.000 of randomic IPs and calculate a lookup average time.

  --coverage [-v] [--with-ipv6]
                      Shows a statistic of how many IPs are covered by current dat file. 
                      
  --missing-ips [-v] [--with-ipv6]
                      Print all IP networks that doesn't have geo information (only for IPv4).
             
Automatic update:
  --update-all [-v]    Download all dat.gz files available in the repository below:
                       {GEOIP_UPDATE_DAT_URL}

  --update-file <geoip2fast_dat_filename> [-v]
                       Download a specific filename from the repository. Only one file is allowed.
                       Allowed values: geoip2fast.dat.gz OR geoip2fast-ipv6.dat.gz OR 
                                       geoip2fast-asn.dat.gz OR geoip2fast-asn-ipv6.dat.gz OR
                                       geoip2fast-city.dat.gz OR geoip2fast-city-ipv6.dat.gz OR 
                                       geoip2fast-city-asn.dat.gz OR geoip2fast-city-asn-ipv6.dat.gz

  --dest <a directory path or a filename> [-v]
                       Specify the destination directory for the downloaded files. When combined with 
                       the '--update-file' parameter, you can specify an existing directory, with or 
                       without a file name, or you can just specify a file name. In the absence of 
                       this parameter or directory information, the library directory will be used 
                       as default value. This parameter is optional. The filename must end 
                       with .dat.gz extension.

                       Use the verbose parameter (-v) if you want to see the download progress, 
                       otherwise there will be no output. You also have to use this parameter 
                       to view possible errors in your console.
               
More options:
  -d                  Resolves the DNS of the given IP address.
  -i / --info         Returns detailed information about the data file currently in use.
  -h / --help         Show this help text.
  -v                  Verbose mode.
  -vvv                Shows the location of current dat file in use.
  
  """)
            
if __name__ == "__main__":
    sys.exit(main_function())
    
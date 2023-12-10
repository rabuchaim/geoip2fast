#!/usr/bin/env python3
# encoding: utf-8
# -*- coding: utf-8 -*-
"""
GeoIP2Fast - Version v1.1.10

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

What's new in v1.1.10 - 01/Dec/2023
- Automatic download of dat.gz files. Try the commands below:
    from geoip2fast import GeoIP2Fast
    from pprint import pprint
    G = GeoIP2Fast(verbose=True)
    G.get_database_path()
    update_file_result = G.update_file(filename="geoip2fast-asn-ipv6.dat.gz",destination="geoip2fast.dat.gz",verbose=True)
    pprint(update_file_result,sort_dicts=False)
    G.reload_data(verbose=True)
    update_all_result = G.update_all(destination_path="",verbose=True)
    pprint(update_all_result,sort_dicts=False)

What's new in v1.1.9 - 22/Nov/2023
- Fix in memory usage under MacOS
- Fix a problem when loading specific datafiles
- a new method to return the path of the dat.gz file that is currently being used
    from geoip2fast import GeoIP2Fast
    G = GeoIP2Fast(geoip2fast_data_file="/tmp/geoip2fast-asn.dat.gz")
    G.get_database_path()

"""
__appid__   = "GeoIP2Fast"
__version__ = "1.1.10"

import sys, os, math, ctypes, struct, socket, time, subprocess, random, binascii, functools
import urllib.request, urllib.error, urllib.parse, gzip, pickle, json, bisect, time

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
GEOIP_UPDATE_DAT_URL                = "https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/"
GEOIP_POSSIBLE_FILENAMES            = ['geoip2fast.dat.gz',
                                       'geoip2fast-ipv6.dat.gz',
                                       'geoip2fast-asn.dat.gz',
                                       'geoip2fast-asn-ipv6.dat.gz']
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

##──── To enable DEBUG flag just export an environment variable GEOIP2FAST_DEBUG with any value ──────────────────────────────────
##──── Ex: export GEOIP2FAST_DEBUG=1 ─────────────────────────────────────────────────────────────────────────────────────────────
_DEBUG = bool(os.environ.get("GEOIP2FAST_DEBUG",False))
os.environ["PYTHONWARNINGS"]    = "ignore"
os.environ["PYTHONIOENCODING"]  = "utf-8"        
sys.tracebacklimit              = 0

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
def cRed(msg): return '\033[91m'+str(msg)+'\033[0m'
def cBlue(msg): return '\033[94m'+str(msg)+'\033[0m'
def cGrey(msg): return '\033[90m'+str(msg)+'\033[0m'
def cWhite(msg): return '\033[97m'+str(msg)+'\033[0m'
def cYellow(msg): return '\033[93m'+str(msg)+'\033[0m'
def cDarkYellow(msg): return '\033[33m'+str(msg)+'\033[0m'


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

##──── IP MANIPULATION FUNCTIONS ─────────────────────────────────────────────────────────────────────────────────────────────────
ipv4_to_int = lambda ipv4_address: struct.unpack('!I', socket.inet_aton(ipv4_address))[0]
int_to_ipv4 = lambda num: socket.inet_ntoa(struct.pack('!I', num))
ipv6_to_int = lambda ipv6_address: int.from_bytes(socket.inet_pton(socket.AF_INET6, ipv6_address), byteorder='big')
int_to_ipv6 = lambda num: socket.inet_ntop(socket.AF_INET6, binascii.unhexlify(hex(num)[2:].zfill(32)))
##──── Number os possible IPs in a network range. (/0, /1 .. /8 .. /24 .. /30, /31, /32) ─────────────────────────────────────────
##──── Call the index of a list. Ex. numIPsv4[24] (is the number os IPs of a network range class C /24) ────────────────────────────
numIPsv4 = sorted([2**num for num in range(0,33)],reverse=True) # from 0 to 32
numIPsv4.append(0)
numIPsv6 = sorted([2**num for num in range(0,129)],reverse=True) # from 0 to 128
numIPsv6.append(0)
MAX_IPv4 = numIPsv4[0]            

##──── numHosts is the numIPs - 2 ────────────────────────────────────────────────────────────────────────────────────────────────
numHostsv4 = sorted([(2**num)-2 for num in range(0,33)],reverse=True) # from 0 to 32
numHostsv6 = sorted([(2**num)-2 for num in range(0,129)],reverse=True) # from 0 to 128
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

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

##──── Object to store the information obtained by searching an IP address ───────────────────────────────────────────────────────
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
        self.asn = False
        self.is_loaded = False

        self.data_file = ""
        self.verbose = verbose
        self._load_data_text = "" 
        
        ##──── Swap functions code at __init__ to avoid "if verbose=True" and save time ──────────────────────────────────────────────────
        if _DEBUG == False:
            self._print_debug = self._print_verbose_empty
        if verbose == False:
            self._print_verbose = self._print_verbose_empty
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
                        databasePath = self._locate_database_file(geoip2fast_data_file)
                        if databasePath is False:
                            raise GeoIPError("Unable to find GeoIP2Fast database file %s"%(os.path.basename(geoip2fast_data_file)))
                        else:
                            self.data_file = databasePath
                    else:
                        # If any file is specified with the path and is not found, raize an exception
                        raise GeoIPError("Check path of specified file and try again.")
            except Exception as ERR:
                raise GeoIPError("Unable to access the specified file %s. %s"%(geoip2fast_data_file,str(ERR)))
            
        self._load_data(self.data_file, verbose)
    ##──── Function used to avoid "if verbose == True". The code is swaped at __init__ ───────────────────────────────────────────────
    def _print_verbose_empty(self,msg):return
    def _print_verbose_regular(self,msg):
        print(msg,flush=True)

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
        global __DAT_VERSION__, databaseHash, geoipASNList, sliceInfo, geoipMainList, geoipSourceInfo, geoipLocationList
        if self.is_loaded == True:
            return True   
        self._print_verbose = self._print_verbose_regular if verbose == True else self._print_verbose_empty

        startMem = get_mem_usage() 
        startLoadData = time.perf_counter()
        ##──── Try to locate the database file in the directory of the application that called GeoIP2Fast() ─────────────────────────
        ##──── or in the directory of the GeoIP2Fast Library ────────────────────────────────────────────────────────────────────────
        try:
            if gzip_data_file == "":
                gzip_data_file = GEOIP2FAST_DAT_GZ_FILE
                try:
                    databasePath = self._locate_database_file(os.path.basename(gzip_data_file))
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
                inputFile = gzip.open(str(self.data_file),'rb')
            except:
                try:
                    inputFile = open(str(self.data_file).replace(".gz",""),'rb')
                    self.data_file = self.data_file.replace(".gz","")
                except Exception as ERR:
                    raise GeoIPError(f"Unable to find {gzip_data_file} or {gzip_data_file} {str(ERR)}")
        except Exception as ERR:
            raise GeoIPError(f"Failed to 'load' GeoIP2Fast! the data file {gzip_data_file} appears to be invalid or does not exist! {str(ERR)}")

        self._database_path = self.data_file
        ##──── Use -vvv on command line to see which dat.gz file is currently being used ─────────────────────────────────────────────────
        if '-vvv' in sys.argv: 
            print(f"Using datafila: {self.data_file}")
            sys.exit(0)

        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────        
        ##──── Load the dat.gz file into memory ──────────────────────────────────────────────────────────────────────────────────────────
        ##──── MODEL OF DATAFILE ─────────────────────────────────────────────────────────────────────────────────────────────────────────
        # database = [__DAT_VERSION__,    # integer
        #             listLocation,       # list      "country_code:country_name"
        #             listAsnNames,       # list 
        #             geoipList,          # geoipList = [mainIndex, mainList, mainListCodes, mainListNetLength, mainIndexASN, mainListASN, mainListASNID]
        #             hashMD5,            # hashmd5 = mainIndex + ":" + lenght of all records
        #             str(sliceInfo),     # string (dict = 'num_keys','total_networks','slice_size''length_last_list')
        #             _SOURCE_INFO]       # string 
        try:
            self.clear_cache()
            __DAT_VERSION__, geoipLocationList, geoipASNList, geoipMainList, databaseHash, sliceInfo, geoipSourceInfo = pickle.load(inputFile)
            if __DAT_VERSION__ != 110:
                raise GeoIPError(f"Failed to pickle the data file {gzip_data_file}. Reason: Invalid version - requires 110, current {str(__DAT_VERSION__)}")
            self.ipv6 = geoipMainList[0][-1] > numIPsv4[0]
            self.asn = len(geoipASNList) > 0
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
                "loaded with %s networks in %.5f seconds and using %.2f MiB."%(str(self._total_networks()),totalLoadTime,totalMemUsage)
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
        return self._load_data(gzip_data_file=self.data_file,verbose=self.verbose)
    
    
    @property
    def startup_line_text(self)->str:
        """
            Returns the text of _load_data() in case you want to know without set verbose=True
            
            Ex: GeoIP2Fast v1.X.X is ready! geoip2fast.dat.gz loaded with XXXXXX networks in 0.0000 seconds and using YY.ZZ MiB
        """
        return self._load_data_text

    def get_database_path(self)->str:
        """
            Returns eturns the path of the currently used data file
        """
        return os.path.realpath(self._database_path)

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
            
            G = GeoIP2Fast(geoip2fast_data_file='geoip2fast-asn-ipv6.dat.gz',verbose=True)
            
            result = G.update_file(filename='geoip2fast-asn-ipv6.dat.gz')
            
            print(result)
            
            G.reload_data()
            
        - 'result' is a status code. Value 0 is OK. Any other value is not OK.

        - 'filename' is the name of dat.gz file. The allowed values are: 'geoip2fast.dat.gz' or 'geoip2fast-ipv6.dat.gz' or 'geoip2fast-asn.dat.gz' or 'geoip2fast-asn-ipv6.dat.gz'
    
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

    @functools.lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=False)
    def _main_index_lookup(self,iplong):
        try:
            matchRoot = bisect.bisect_right(geoipMainList[0],iplong)-1
            matchChunk = bisect.bisect_right(geoipMainList[1][matchRoot],iplong)-1
            first_ip2int = geoipMainList[1][matchRoot][matchChunk]
            if iplong <= MAX_IPv4:
                last_ip2int = first_ip2int + numIPsv4[geoipMainList[3][matchRoot][matchChunk]]-1
            else:
                last_ip2int = first_ip2int + numIPsv6[geoipMainList[3][matchRoot][matchChunk]]-1
            return matchRoot, matchChunk, first_ip2int, last_ip2int
        except Exception as ERR:
            return GeoIPError("Failed at _main_index_lookup: %s"%(str(ERR)))
                
    @functools.lru_cache(maxsize=DEFAULT_LRU_CACHE_SIZE, typed=False)
    def _asn_lookup(self,iplong):
        try:
            matchRoot = bisect.bisect_right(geoipMainList[4],iplong)-1
            matchChunk = bisect.bisect_right(geoipMainList[5][matchRoot],iplong)-1
            return geoipASNList[geoipMainList[6][matchRoot][matchChunk]]
        except:
            return ""
                        
    @functools.lru_cache(maxsize=300, typed=True)
    def _country_lookup(self,country_code_index):
        try:
            country_code, country_name = geoipLocationList[country_code_index].split(":")
            is_private = country_code_index <= 15
            country_code = self.error_code_private_networks if is_private else country_code
            return country_code, country_name, is_private
        except Exception as ERR:
            return GeoIPError("Failed at _country_lookup: %s"%(str(ERR)))

    def _ip2int(self,ipaddr:str)->int:
        """
        Convert an IP Address into an integer number
        """    
        try:
            try:
                return int(struct.unpack('!I', socket.inet_aton(ipaddr))[0])
            except:
                return int.from_bytes(socket.inet_pton(socket.AF_INET6, ipaddr), byteorder='big')
        except Exception as ERR:
            raise GeoIPError("Failed at ip2int: %s"%(str(ERR)))

    def _int2ip(self,iplong:int)->str:
        """
        Convert an integer to IP Address
        """    
        try:
            if iplong <= MAX_IPv4:
                return socket.inet_ntoa(struct.pack('!I', iplong))
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
            matchRoot, matchChunk, first_ip2int, last_ip2int = self._main_index_lookup(iplong)
            if iplong > last_ip2int:
                return GeoIPDetail(ip=ipaddr,country_code=self.error_code_network_not_found, \
                            country_name=GEOIP_NOT_FOUND_STRING,elapsed_time='%.9f sec'%(time.perf_counter()-startTime))
            country_code, country_name, is_private = self._country_lookup(geoipMainList[2][matchRoot][matchChunk])
            cidr = self._int2ip(first_ip2int)+"/"+str(geoipMainList[3][matchRoot][matchChunk])        
            asn_name = self._asn_lookup(iplong) if self.asn == True else ""
            ##──── SUCCESS! ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            return GeoIPDetail(ipaddr,country_code,country_name,cidr,is_private,asn_name,elapsed_time='%.9f sec'%((time.perf_counter()-startTime)))
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
                "lastip_lookup "+str(self._asn_lookup.cache_info()),\
                "country_lookup "+str(self._country_lookup.cache_info())
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
    
    def self_test(self,max_ips=30):
        """
            Do a self-test with some random IPs
        """                
        ip_list = ['266.266.266.266','192,0x0/32','10.20.30.40']
        if self.ipv6 == True:
            ipv6_list = ['2606:54c0:19e0::','2606:54c0:1e40::','2606:54c0:1e40::','2a13:3f86:6e00::',
                         '2c0f:fed8:1000::','2c0f:feb0:1000::','2c0f:fe40:8001::','2c0f:f518::','2c0f:7c00::',
                         '2a13:df80:8800::','2a13:d00:8000::','2a13:aac7:1000::','2a12:dd47:db78::',
                         '2a13:a5c5:2000::','2a13:8880::','2a13:5600::','2a13:3f87:ab00::','2a13:3f86:f600::',
                         '2a13:3f85:c000::','2a13:b487:501c::']
            random.shuffle(ipv6_list)
            ip_list.extend(ipv6_list[:10])
        avgList, avgCacheList = [], []
        while len(ip_list) < max_ips:
            ip_list.append(f"{self._int2ip(random.randint(16777216,3758096383))}")
        for IP in ip_list:
            geoip = self.lookup(IP)
            avgList.append(float(geoip.elapsed_time.split(" ")[0]))
            cachedResult = self.lookup(IP)
            avgCacheList.append(float(cachedResult.elapsed_time.split(" ")[0]))
            print("> "+cWhite(IP.ljust(16))+" "+str(geoip.country_code).ljust(3)+cWhite(str(geoip.country_name).ljust(33))+ \
                " ["+cWhite(geoip.elapsed_time)+"]  Cached > ["+cWhite(cachedResult.elapsed_time)+"] "+cachedResult.asn_name[:42])
        print("")
        print("Self-test with %s randomic IP addresses."%(format_num(len(ip_list))))
        # Discard the best and worst elapsed_time before calculate average
        print("\t- Average Lookup Time: %.9f seconds. "%(sum(sorted(avgList)[1:-1])/(len(ip_list)-2)))
        print("\t- Average Cached Lookups: %.9f seconds. "%(sum(sorted(avgCacheList)[1:-1])/(len(ip_list)-2)))
        print("")

    def random_test(self,max_ips=1000000):
        """
            Do a self-test with 1.000.000 of randomic IPs
        """        
        MAX_IPS = max_ips
        random_iplist = []
        startTime = time.perf_counter()
        for I in range(MAX_IPS):
            random_iplist.append(f"{self._int2ip(random.randint(16777216,3758096383))}")
        print(f"List of {format_num(MAX_IPS)} of randomic IPs created in {'%.2f seconds'%(time.perf_counter()-startTime)}")
        print("")
        if max_ips > 100:
            for I in range(5,0,-1):
                print(f"\rStart in {I} second(s)...",end="")
                time.sleep(1)
            print("\r")
        avgList, avgCacheList = [], []
        startTime = time.perf_counter()
        for IP in random_iplist:
            geoip = self.lookup(IP)
            avgList.append(float(geoip.elapsed_time.split(" ")[0]))
            cachedResult = self.lookup(IP)
            avgCacheList.append(float(cachedResult.elapsed_time.split(" ")[0]))   
            print("> "+cWhite(IP.ljust(15))+" "+str(geoip.country_code).ljust(3)+cWhite(str(geoip.country_name).ljust(33))+ \
                " ["+cWhite(geoip.elapsed_time)+"]  Cached > ["+cWhite(cachedResult.elapsed_time)+"] "+cachedResult.asn_name[:42])
        print("")
        print("Random test with %s randomic IP addresses."%(format_num(MAX_IPS)))
        # Discard the best and worst elapsed_time before calculate average
        print("\t- Average Lookup Time: %.9f seconds. "%(sum(sorted(avgList)[1:-1])/(MAX_IPS-2)))
        print("\t- Average Cached Lookups: %.9f seconds. "%(sum(sorted(avgCacheList)[1:-1])/(MAX_IPS-2)))
        print("")
               
    def show_missing_ips(self,verbose=False):
        """
            Scan database for network ranges without geographic information. 
        """        
        total_missing_ips = 0
        total_missing_networks = 0
        classDict = {}
        try:
            startTime = time.perf_counter()
            for N in range(len(geoipMainList[1])-1):
                for I in range(len(geoipMainList[1][N])-1):
                    first_iplong = geoipMainList[1][N][I]
                    if first_iplong <= numIPsv4[0]:
                        first_ipstring = self._int2ip(geoipMainList[1][N][I])
                        last_iplong = geoipMainList[1][N][I] + numIPsv4[geoipMainList[3][N][I]] - 1
                        if first_iplong == 0:
                            old_last_iplong = last_iplong
                            continue
                        if first_iplong - old_last_iplong > 1:
                            miss_first_iplong = old_last_iplong + 1
                            miss_last_iplong = first_iplong - 1
                            missing_ips = miss_last_iplong - miss_first_iplong + 1
                            if missing_ips > 0:
                                if math.log(missing_ips, 2).is_integer() == False:
                                    cidr = cGrey("<unknown>".center(18))
                                else: # if number of missing IPs is power of 2
                                    cidr = cWhite((first_ipstring+"/"+str(numIPsv4.index(missing_ips))).ljust(18))
                                if classDict.get(first_ipstring.split(".")[0],"X") == "X":
                                    classDict[first_ipstring.split(".")[0]] = 0
                                classDict[first_ipstring.split(".")[0]] += missing_ips
                                total_missing_networks += 1
                                for IP in range(miss_first_iplong,miss_last_iplong+1):
                                    test = self.lookup(self._int2ip(miss_first_iplong)).to_dict()
                                    if test['country_code'] != "--":
                                        classDict[first_ipstring.split(".")[0]] -= 1
                                        missing_ips -= 1
                                if missing_ips > 0:
                                    print(f"From {cWhite(self._int2ip(miss_first_iplong).ljust(15))} to {cWhite(self._int2ip(miss_last_iplong).ljust(15))} > Network {cidr} > Missing IPs: {cWhite(missing_ips)}")
                                    total_missing_ips += missing_ips
                        old_last_iplong = last_iplong
            total_missing_networks -= 13 # 14 special networks first IPs - 1 reserved for broadcast that is included in 240.0.0.0/4
            total_missing_ips += total_missing_networks # a difference for the last ip excluded to calc math.power of 2
            if verbose == True:
                print("")
                classDict = dict(sorted(classDict.items(),key=lambda x:int(x[1]), reverse=True))
                classDictOne = {k:v for k,v in classDict.items() if v == 1}
                classDictTwo = {k:v for k,v in classDict.items() if v == 2}
                classDict = {k:v for k,v in classDict.items() if v > 2}
                print("  > Missing IPs per network class:\n")
                for k,v in classDict.items():
                    print(f"    - Class {k}.0.0.0/8".ljust(25,'.')+": "+cWhite(f"{format_num(v)}"))
                if len(classDictTwo.keys()) > 0:
                    logString = "    - Class "
                    for key in classDictTwo.keys():
                        logString += key+".0.0.0/8, "
                        if (list(classDictTwo.keys()).index(key) + 1) % 5 == 0:
                            logString += "\n      "
                    logString = logString[:-2]+"..: "+cWhite("2 (each one)")
                    print(logString)                    
                if len(classDictOne.keys()) > 0:
                    logString = "    - Class "
                    for key in classDictOne.keys():
                        logString += key+".0.0.0/8, "
                        if (list(classDictOne.keys()).index(key) + 1) % 5 == 0:
                            logString += "\n      "
                    logString = logString[:-2]+"..: "+cWhite("1 (each one)")
                    print(logString)
            print("")
            percentage = (total_missing_ips * 100) / numIPsv4[0]
            print(f">>> Valid IP addresses without geo information: {cYellow(format_num(total_missing_ips))} (%.2f%% of all IPv4) [%.5f sec]"%(percentage,time.perf_counter()-startTime))
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
            startTime = time.perf_counter()
            ipCounterv4, ipCounterv6 = 0, 0
            index = 0
            totalNetworksv4, totalNetworksv6  = 0, 0
            for indexList in geoipMainList[3]:
                indexListCounter = 0
                for item in indexList:
                    startTimeCIDR = time.perf_counter()
                    num_ipsv4 = 0
                    num_ipsv6 = 0                 
                    if geoipMainList[1][index][indexListCounter] <= numIPsv4[0]:
                        num_ipsv4 = numIPsv4[item]
                        num_ips = num_ipsv4
                        totalNetworksv4 += 1
                    else:
                        num_ipsv6 = numIPsv6[item]
                        num_ips = num_ipsv6
                        totalNetworksv6 += 1
                    ipCounterv4 += num_ipsv4
                    ipCounterv6 += num_ipsv6
                    if verbose and print_result == True:
                        IP = str(self._int2ip(geoipMainList[1][index][indexListCounter]))
                        CIDR = IP + "/" + str(item)
                        result = self.lookup(IP)
                        print(f"- Network: {cWhite(CIDR.ljust(19))} IPs: {cWhite(str(num_ips).ljust(10))} {result.country_code} {cWhite(result.country_name.ljust(35))} {'%.9f sec'%(time.perf_counter()-startTimeCIDR)}")
                    indexListCounter += 1
                index += 1                        
            ipCounterv4 -= 1 # removing the last IP (255.255.255.255) that is already included in 240.0.0.0/4
            percentagev4 = (ipCounterv4 * 100) / numIPsv4[0]
            percentagev6 = (ipCounterv6 * 100) / numIPsv6[0]
            endTime = time.perf_counter()
            if print_result == True:
                if verbose: print("")
                print(f"Current IPv4 coverage: %s ({format_num(ipCounterv4)} IPv4 in %s networks) [%.5f sec]"%(str('%.2f%%'%(percentagev4)).rjust(7),totalNetworksv4,(endTime-startTime)))
                print(f"Current IPv6 coverage: %s ({format_num(ipCounterv6)} IPv6 in %s networks) [%.5f sec]"%(str('%.2f%%'%(percentagev6)).rjust(7),totalNetworksv6,(endTime-startTime)))
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
            # IT MAY BE FASTER IF YOU CREATE THE IP LIST BEFORE STARTING SEARCHES.
            # BUT LET´S KEEP LIKE THIS TO SPEND SOME MILLISECONDS TO GET CLOSER A REAL SITUATION OF USE
            for NUM in range(MAX_IPS):
                IP = self._int2ip(random.randint(16777216,3758096383)) # from 1.0.0.0 to 223.255.255.255
                ipinfo = self.lookup(IP)
                XXXX = ipinfo.country_code # SIMULATE THE USE OF THE RETURNED VALUE
            total_time_spent = time.perf_counter() - startTime
            current_lookups_per_second = MAX_IPS / total_time_spent
            if print_result == True:
                print("Current speed: %.2f lookups per second (%s IPs with an average of %.9f second per lookup) [%.5f sec]"%(current_lookups_per_second,format_num(MAX_IPS),total_time_spent / MAX_IPS,time.perf_counter()-startTime))
            return current_lookups_per_second
        except Exception as ERR:
            raise GeoIPError("Failed to calculate current speed. %s"%(str(ERR)))

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
    if '-v' in sys.argv: 
        verbose_mode = True
        sys.argv.pop(sys.argv.index('-v'))
        ncmd -= 1
    if '-d' in sys.argv: 
        resolve_hostname = True
        sys.argv.pop(sys.argv.index('-d'))
        ncmd -= 1

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
    
    if '--speed-test' in sys.argv or '--speedtest' in sys.argv:
        geoip = GeoIP2Fast(verbose=True)
        print("\nCalculating current speed... wait a few seconds please...\n")
        geoip.calculate_speed(print_result=True)
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
        geoip.show_missing_ips(verbose=verbose_mode)
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
        geoip.calculate_coverage(print_result=True,verbose=verbose_mode)
        print("")
        sys.exit(0)
    if len(sys.argv) > 1 and sys.argv[1] is not None and '-h' not in sys.argv:
        a_list = sys.argv[1].replace(" ","").split(",")
        if len(a_list) > 0:
            geoip = GeoIP2Fast(verbose=verbose_mode)
            for IP in a_list:
                result = geoip.lookup(str(IP))
                if resolve_hostname == True: result.get_hostname()
                result.pp_json(print_result=True)
    else:
        print(f"GeoIP2Fast v{__version__} Usage: {os.path.basename(__file__)} [-h] [-v] [-d] <ip_address_1>,<ip_address_2>,<ip_address_N>,...")
        if '-h' in sys.argv:
            print(f'''
Testing parameters:
  --self-test          Starts a self-test with some randomic IP addresses.
  --speed-test         Starts a lookups per second test with 1 million random IP addresses.
  --random-test        Starts a test with 1 million random IPs and calculate the average lookup time.

  --coverage [-v]      Shows a statistic of how many IPs are covered by current dat file. 
  --missing-ips [-v]   Print all IP networks that doesn't have geo information (only for IPv4).

Automatic update:
  --update-all [-v]    Download all dat.gz files available in the repository below:
                       {GEOIP_UPDATE_DAT_URL}

  --update-file <geoip2fast_dat_filename> [-v]
                       Download a specific filename from the repository. Only one file is allowed.
                       Allowed values are: geoip2fast.dat.gz OR geoip2fast-ipv6.dat.gz OR 
                                           geoip2fast-asn.dat.gz OR geoip2fast-asn-ipv6.dat.gz

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
  -d                   Resolve the DNS of given IP address.
  -h                   Show this help text.
  -v                   Verbose mode.
  -vvv                 Shows the location of current dat file in use.
  
  ''')
            
if __name__ == "__main__":
    sys.exit(main_function())
    
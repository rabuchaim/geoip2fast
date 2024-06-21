#!/usr/bin/env python3
# encoding: utf-8
# -*- coding: utf-8 -*-
"""
GeoIP2Dat v1.2.2 - DAT file update for GeoIP2Fast
"""
"""
Author: Ricardo Abuchaim - ricardoabuchaim@gmail.com
        https://github.com/rabuchaim/geoip2fast/

License: MIT
"""
__appid__   = "GeoIP2Dat"
__version__ = "1.2.2"

import sys, os, gzip, pickle, io, socket, struct, json, hashlib, csv, shutil
import ctypes, subprocess
from datetime import datetime as dt
from binascii import unhexlify
from bisect import bisect as geoipBisect
from argparse import ArgumentParser, HelpFormatter, SUPPRESS
from contextlib import contextmanager
from timeit import default_timer
from pprint import pprint as pp

##──── URL TO DOWNLOAD CSV FILES FROM MAXMIND (FOR FUTURE VERSIONS) ───────────────────────────────────────────────────────────────────────────────────
# MM_URL_COUNTRY  = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip"
# MM_URL_CITY     = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip"
# MM_URL_ASN      = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip"
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
##──── MAXMIND STANDARD FILENAMES ────────────────────────────────────────────────────────────────────────────────────────────────
MM_COUNTRY_LOCATIONS_FILENAME   = "GeoLite2-Country-Locations-XX.csv"
MM_COUNTRY_BLOCKS_IPV4_FILENAME = "GeoLite2-Country-Blocks-IPv4.csv"
MM_COUNTRY_BLOCKS_IPV6_FILENAME = "GeoLite2-Country-Blocks-IPv6.csv"
MM_CITY_LOCATIONS_FILENAME      = "GeoLite2-City-Locations-XX.csv"
MM_CITY_BLOCKS_IPV4_FILENAME    = "GeoLite2-City-Blocks-IPv4.csv"
MM_CITY_BLOCKS_IPV6_FILENAME    = "GeoLite2-City-Blocks-IPv6.csv"
MM_ASN_BLOCKS_IPV4_FILENAME     = "GeoLite2-ASN-Blocks-IPv4.csv"
MM_ASN_BLOCKS_IPV6_FILENAME     = "GeoLite2-ASN-Blocks-IPv6.csv"
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
##──── GEOIP2FAST FILENAME ───────────────────────────────────────────────────────────────────────────────────────────────────────
GEOIP2FAST_DAT_FILENAME_GZ      = "geoip2fast.dat.gz"

DEFAULT_SOURCE_INFO             = "MAXMIND:GeoLite2-"

LIST_SLICE_SIZE                 = 100
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
AVAILABLE_LANGUAGES     = ['de','en','es','fr','ja','pt-BR','ru','zh-CN']

__DAT_VERSION__         = 120
terminalWidth           = 100

sys.tracebacklimit      = 0
doubleLine              = "═"
singleLine              = "─"
middot                  = "\xb7"

##──── To enable DEBUG flag just export an environment variable GEOIP2DAT_DEBUG with any value ──────────────────────────────────
##──── Ex: export GEOIP2DAT_DEBUG=1 ─────────────────────────────────────────────────────────────────────────────────────────────
_DEBUG = bool(os.environ.get("GEOIP2DAT_DEBUG",False))

os.environ["PYTHONWARNINGS"]    = "ignore"
os.environ["PYTHONIOENCODING"]  = "UTF-8"        


# https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv
# https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv

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
    "255.255.255.255/32":{"14":"Reserved for broadcast"},
    "fd00::/8":          {"15":"Reserved for Unique Local Addresses"},
    }

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
    return socket.inet_ntop(socket.AF_INET6, unhexlify(hex(iplong)[2:].zfill(32)))

##──── Number os possible IPs in a network range. (/0, /1 .. /8 .. /24 .. /30, /31, /32) ─────────────────────────────────────────
##──── Call the index of a list. Ex. numIPs[24] (is the number os IPs of a network range class C /24) ────────────────────────────
numIPsv4 = sorted([2**num for num in range(0,33)],reverse=True) # from 0 to 32
numIPsv4.append(0)
numIPsv6 = sorted([2**num for num in range(0,129)],reverse=True) # from 0 to 128
numIPsv6.append(0)
##──── numHosts is the numIPs - 2 ────────────────────────────────────────────────────────────────────────────────────────────────
numHostsv4 = sorted([(2**num)-2 for num in range(0,33)],reverse=True) # from 0 to 32
numHostsv6 = sorted([(2**num)-2 for num in range(0,129)],reverse=True) # from 0 to 128
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

##──── GET MEMORY USAGE ───────────────────────────────────────────────────────────────────────────────────────────────────────
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

def get_mem_usage()->float:
    ''' Memory usage in MiB '''
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
##───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
##──── Functions to print to stdout ─────────────────────────────────────────────────────────────────────────────────────────────────
def _log_empty(msg,end=""):return
def log(msg,end="\n"):
    print(msg,end=end,flush=True)
def logVerbose(msg,end="\n"):
    print(msg,end=end,flush=True)
def logDebug(msg,end="\n"):
    print(cDarkYellow("- [DEBUG] "+msg),end=end,flush=True)
def logError(msg,end="\n"):
    print(cRed("- [ERROR] "+msg),end=end,flush=True)
def logMemory(msg,end="\n"):
    print(cBlue("- [MEMORY] "+msg),end=end,flush=True)
##──── TEXT REPEAT UNTIL - Repeat a text until max_length ───────────────────────────────────────────────────────────────────────────
tru = lambda text, max_length=100: (text * (max_length // len(text))) + text[:max_length % len(text)] if len(text) > 0 else ''
##──── Return date with no spaces to use with filenames ─────────────────────────────────────────────────────────────────────────────
get_date = lambda: dt.now().strftime('%Y%m%d%H%M%S')
##──── RETURN A MD5SUM HASH OF A STRING ─────────────────────────────────────────────────────────────────────────────────────────────
get_md5 = lambda stringToHash="": hashlib.md5(f"{str(stringToHash)}".encode()).hexdigest()
##──── Default formatter for json to avoid datetime errors ──────────────────────────────────────────────────────────────────────────
json_default_formatter = lambda o: o.__str__ if isinstance(o, (dt.date, dt.datetime)) else None
##──── ANSI colors ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
def cRed(msg): return '\033[91m'+str(msg)+'\033[0m'
def cBlue(msg): return '\033[94m'+str(msg)+'\033[0m'
def cGrey(msg): return '\033[90m'+str(msg)+'\033[0m'
def cWhite(msg): return '\033[97m'+str(msg)+'\033[0m'
def cYellow(msg): return '\033[93m'+str(msg)+'\033[0m'
def cDarkYellow(msg): return '\033[33m'+str(msg)+'\033[0m'
##──── A pretty print for json ───────────────────────────────────────────────────────────────────────────────────────────────────
def ppJson(data_dict,indent=3, sort_keys=False, print_result=True):
    """A pretty print for JSON"""
    try:
        dump = json.dumps(data_dict, sort_keys=sort_keys, indent=indent, ensure_ascii=False, default=json_default_formatter)
        if print_result == True:
            print(dump)
        else:
            return dump
    except Exception as ERR:
        raise Exception(f"Failed pp_json() {str(ERR)}")

##──── CLASS TO INTERCEPT INIT, ENTER and EXIT ──────────────────────────────────────────────────────────────────────────────────────
class geoip2dat():
    def __init__(self):
        log(tru(">",terminalWidth))
        log(f">>>>> STARTING {__appid__} v{__version__}")
        log(tru(">",terminalWidth))
    def __enter__(self):
        pass        
    def __exit__(self,type,value,traceback):
        log(tru("<",terminalWidth))
        log(f"<<<<< EXITING {__appid__} PROCESS")
        log(tru("<",terminalWidth))

##──── CLASS FOR ARGUMENT PARSER ────────────────────────────────────────────────────────────────────────────────────────────────────
class class_argparse_formatter(HelpFormatter):
    my_max_help_position = 30
    try:
        ttyCols, ttyRows = shutil.get_terminal_size()
    except:
        ttyCols, ttyRows = 30, 150
    ttyRows = int(ttyRows)
    ttyCols = (int(ttyCols) // 4) * 3
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = 'Usage: '
        return super(class_argparse_formatter, self).add_usage(usage, actions, groups, prefix)
    def _format_usage(self, usage, actions, groups, prefix):
        return super(class_argparse_formatter, self)._format_usage(usage, actions, groups, prefix)
    def add_text(self, text):
        if text is not SUPPRESS and text is not None:
            if text.startswith('1|'):   # 1| before the text give space of 2 lines
                text = str(text[2:]+"\n\n")
            return super()._add_item(self._format_text, [text])
    def _split_lines(self, text, width): # 0| before the text there is no space between lines
        if text.startswith('0|'):
            return text[2:].splitlines()
        return super()._split_lines(text, width=class_argparse_formatter.ttyCols-class_argparse_formatter.my_max_help_position-5) + ['']
    def _format_action(self, action):
        self._max_help_position = class_argparse_formatter.my_max_help_position
        self._indent_increment = 2
        self._width = class_argparse_formatter.ttyCols
        return super(class_argparse_formatter, self)._format_action(action)
    
##──── Calculate information about a CIDR ───────────────────────────────────────────────────────────────────────────────────────────
class CIDRv4Detail(object):
    """An object to calculate some information about a CIDR, with some properties
       calculated on demand. This is necessary just because we need the first and last
       IP of a network converted to integer and the number of hosts used in coverage test.

       There are a lot of ways to get this information using ipaddress, netaddr, etc, but this
       is the fastest method tested.
    """
    def __init__(self,CIDR):  # CIDR like 1.2.3.0/24, 10.0.0.0/8
        addr, nlen = CIDR.split('/')
        self.cidr = CIDR
        self.addr = addr
        self.nlen = int(nlen)   # network length
        self.is_ipv4 = True
        self.is_ipv6 = False
    @property
    def first_ip(self)->str:
        return self.addr
    @property
    def last_ip(self)->str:
        return int_to_ipv4(self.first_ip2int+int(numIPsv4[self.nlen])-1)
    @property
    def first_ip2int(self)->int:
        return ipv4_to_int(self.addr)
    @property
    def last_ip2int(self)->int:
        return ipv4_to_int(self.last_ip)
    @property
    def num_ips(self)->int:
        return numIPsv4[self.nlen]
    @property
    def num_hosts(self)->int:
        return numHostsv4[self.nlen]
##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
class CIDRv6Detail(object):
    """An object to calculate some information about a CIDR of an IPv6
    """
    def __init__(self,CIDR):  # CIDR like 1.2.3.0/24, 10.0.0.0/8
        addr, nlen = CIDR.split('/')
        self.cidr = CIDR
        self.addr = addr
        self.nlen = int(nlen)   # network length
        self.is_ipv4 = False
        self.is_ipv6 = True
    @property
    def first_ip(self)->str:
        return self.addr
    @property
    def last_ip(self)->str:
        return int_to_ipv6(self.first_ip2int+numIPsv6[self.nlen]-1)
    @property
    def first_ip2int(self)->int:
        return ipv6_to_int(self.addr)
    @property
    def last_ip2int(self)->int:
        return ipv6_to_int(self.last_ip)
    @property
    def num_ips(self)->int:
        return numIPsv6[self.nlen]
    @property
    def num_hosts(self)->int:
        return numHostsv6[self.nlen]
##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

class GeoIP2DatError(Exception):
    def __init__(self, message):
        self.message = message
    def __str__(self):
        return self.message

##──── CLOCK ELAPSED TIME ────────────────────────────────────────────────────────────────────────────────────────────────────────
@contextmanager
def elapsed_timer():
    start = default_timer()
    elapsed = lambda: default_timer() - start
    yield lambda: elapsed()
    end = default_timer()
    elapsed = lambda: end-start
    
def timer(elapsed_timer_name): 
    try:
        return "[%.6f sec]"%elapsed_timer_name
    except:
        try:
            return "[%.6f sec]"%elapsed_timer_name()
        except:
            return "[error sec]"
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

##──── Join the splitted list ────────────────────────────────────────────────────────────────────────────────────────────────────
def join_list(list_of_lists):
    joined_list = []
    for sublist in list_of_lists:
        joined_list.extend(sublist)
    return joined_list
##───────────────────────────'─────────────────────────────────────────────────────────────────────────────────────────────────────
def split_list(lista, n):
    sliced_lists = []
    for i in range(0, len(lista), n):
        sliced_lists.append(lista[i:i + n])
    return sliced_lists
##───────────────────────────'─────────────────────────────────────────────────────────────────────────────────────────────────────
def split_dict(iterable, start, stop):
    from itertools import islice
    return islice(iterable, start, stop)
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

##################################################################################################################################
##################################################################################################################################

                         ########     ##     ##    ##    ## 
                         ##     ##    ##     ##    ###   ## 
                         ##     ##    ##     ##    ####  ## 
                         ########     ##     ##    ## ## ## 
                         ##   ##      ##     ##    ##  #### 
                         ##    ##     ##     ##    ##   ### 
                         ##     ##     #######     ##    ## 
 
##################################################################################################################################
##################################################################################################################################
#defrun
def run(country_dir,asn_dir,city_dir,output_dir,language="en",source_info="",debug=False,with_ipv6=False,mini=False):
    if source_info == "":
        tempText = ""
        if mini == True:
            tempText = "CountryMin-IPv4"
        else:
            if country_dir != "":
                tempText += 'Country'
            if city_dir != "":
                tempText += 'City'
            if asn_dir != "":
                tempText += 'ASN'
            if with_ipv6 == True:
                tempText += '-IPv4IPv6'
            else:
                tempText += '-IPv4'
        tempText += "-"+language.replace('-','')+"-"+str(get_date()[:8])
        source_info = DEFAULT_SOURCE_INFO+tempText    
    logMemory.__code__ = _log_empty.__code__
    if debug == False:
        logDebug.__code__ = _log_empty.__code__
    with elapsed_timer() as elapsed_total:
        if language not in AVAILABLE_LANGUAGES:
            raise GeoIP2DatError(F"Invalid language. Valid options are {str(AVAILABLE_LANGUAGES)[1:-1]}")
        ##──── Check the directories and filenames ───────────────────────────────────────────────────────────────────────────────────────
        try:
            with elapsed_timer() as elapsed:
                if country_dir != "":
                    if not os.path.isdir(country_dir):
                        raise GeoIP2DatError("Invalid country CSV files directory. %s"%(country_dir))
                    if not os.path.isfile(os.path.join(country_dir,MM_COUNTRY_LOCATIONS_FILENAME.replace("XX",language))):
                        raise GeoIP2DatError("Unable to access the file %s in directory %s"%(MM_COUNTRY_LOCATIONS_FILENAME.replace("XX",language),country_dir))
                    if not os.path.isfile(os.path.join(country_dir,MM_COUNTRY_BLOCKS_IPV4_FILENAME)):
                        raise GeoIP2DatError("Unable to access the file %s in directory %s"%(MM_COUNTRY_BLOCKS_IPV4_FILENAME,country_dir))
                    if with_ipv6 == True:
                        if not os.path.isfile(os.path.join(country_dir,MM_COUNTRY_BLOCKS_IPV6_FILENAME)):
                            raise GeoIP2DatError("Unable to access the file %s in directory %s"%(MM_COUNTRY_BLOCKS_IPV6_FILENAME,country_dir))
                if city_dir != "":
                    if not os.path.isdir(city_dir):
                        raise GeoIP2DatError("Invalid city CSV files directory. %s"%(city_dir))
                    if not os.path.isfile(os.path.join(city_dir,MM_CITY_LOCATIONS_FILENAME.replace("XX",language))):
                        raise GeoIP2DatError("Unable to access the file %s in directory %s"%(MM_CITY_LOCATIONS_FILENAME.replace("XX",language),city_dir))
                    if not os.path.isfile(os.path.join(city_dir,MM_CITY_BLOCKS_IPV4_FILENAME)):
                        raise GeoIP2DatError("Unable to access the file %s in directory %s"%(MM_CITY_BLOCKS_IPV4_FILENAME,city_dir))
                    if with_ipv6 == True:
                        if not os.path.isfile(os.path.join(city_dir,MM_CITY_BLOCKS_IPV6_FILENAME)):
                            raise GeoIP2DatError("Unable to access the file %s in directory %s"%(MM_CITY_BLOCKS_IPV6_FILENAME,city_dir))
                if asn_dir != "":
                    if not os.path.isdir(asn_dir):
                        raise GeoIP2DatError("Invalid ASN CSV files directory. %s"%(asn_dir))
                    if not os.path.isfile(os.path.join(asn_dir,MM_ASN_BLOCKS_IPV4_FILENAME)):
                        raise GeoIP2DatError("Unable to access the file %s in directory %s"%(MM_ASN_BLOCKS_IPV4_FILENAME,asn_dir))
                    if with_ipv6 == True:
                        if not os.path.isfile(os.path.join(asn_dir,MM_ASN_BLOCKS_IPV6_FILENAME)):
                            raise GeoIP2DatError("Unable to access the file %s in directory %s"%(MM_ASN_BLOCKS_IPV6_FILENAME,asn_dir))                    
                if not os.path.isdir(output_dir):
                    raise GeoIP2DatError("Invalid output directory. %s"%(output_dir))
                log(f"- Checking directories... done! {timer(elapsed())}")
        except Exception as ERR:
            logError("Failed at directories check. %s"%(str(ERR)))
            return 1
        try:
            with elapsed_timer() as elapsed:
                if os.path.isfile(os.path.join(output_dir,GEOIP2FAST_DAT_FILENAME_GZ)):
                    oldFile = os.path.join(output_dir,GEOIP2FAST_DAT_FILENAME_GZ)
                    newFile = os.path.join(output_dir,GEOIP2FAST_DAT_FILENAME_GZ.split(".")[0]+"-"+get_date()+"."+(".".join(GEOIP2FAST_DAT_FILENAME_GZ.split(".")[1:])))
                    if _DEBUG == True:
                        logDebug(f"OldFile: {oldFile} - NewFile: {newFile}")
                    try:
                        ##──── If the process of creation fails, the rename will be rolled back ──────────────────────────────────────────────────────────
                        os.rename(oldFile,newFile)
                        log(f"- Renaming file {oldFile} to {newFile}... done! {timer(elapsed())}")
                    except Exception as ERR:
                        raise GeoIP2DatError(f"Failed to rename existing file {GEOIP2FAST_DAT_FILENAME_GZ}. %s"%(str(ERR)))
        except Exception as ERR:
            logError("%s"%(str(ERR)))
            return 1
        
        log("- Source info: "+cYellow(source_info))

        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

           #        #####     #     #
          # #      #     #    ##    #
         #   #     #          # #   #
        #     #     #####     #  #  #
        #######          #    #   # #
        #     #    #     #    #    ##
        #     #     #####     #     #
        
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        dictGeoAsn = {}
        dictNamesAsnByName = {}
        dictNamesAsnByID = {}
        listFirstIPASN = []
        asn_new_id = 0
        if asn_dir != "":
            logMemory(f"%.2f MiB"%(get_mem_usage()))
            dictNamesAsnByName['<unknown>'] = 0
            file_list = [MM_ASN_BLOCKS_IPV4_FILENAME]
            if with_ipv6 == True:
                file_list.append(MM_ASN_BLOCKS_IPV6_FILENAME)
            for FILE in file_list:
                is_IPV6 = FILE.find("v6") >= 0            
                log(f"- Starting read lines from CSV file {FILE}")
                counter = 0
                with elapsed_timer() as elapsed:
                    try:
                        with io.open(os.path.join(asn_dir, FILE.replace("XX", language)), mode="rt", encoding="utf-8") as f:
                            next(f)  # skip the first line (the CSV's header)
                            reader = csv.reader(f, delimiter=',', quotechar='"')
                            for fields in reader:
                                try:
                                    counter += 1
                                    cidr, asn_id, asn_name = map(str.strip, fields[:3])
                                    if is_IPV6:
                                        CIDRInfo = CIDRv6Detail(cidr)
                                    else:
                                        CIDRInfo = CIDRv4Detail(cidr)
                                    firstIP = CIDRInfo.first_ip2int
                                    lastIP = CIDRInfo.last_ip2int
                                    if dictNamesAsnByName.get(asn_name, 0) == 0:
                                        asn_new_id += 1
                                        dictNamesAsnByName[asn_name] = asn_new_id
                                        asn_id = asn_new_id
                                    else:
                                        asn_id = dictNamesAsnByName[asn_name]
                                    dictGeoAsn[firstIP] = {
                                        'asn_cidr': cidr,
                                        'asn_id': asn_id,
                                        'asn_name': asn_name,
                                        'last_ip': lastIP
                                    }
                                except Exception as ERR:
                                    logError(f"Error at line {counter} - {str(ERR)}")
                                if counter % 10000 == 0:
                                    # break
                                    log(f"\r> Lines read: {counter}", end="")
                            log(f"\r- Lines read: {counter} done! {timer(elapsed())}")
                    except Exception as ERR:
                        logError(f"Failed reading ASN file {str(ERR)}")
                        return 1
            with elapsed_timer() as elapsed:
                try:
                    asn_new_id += 1
                    asn_name = "IANA.ORG"
                    new_networks = 0
                    dictNamesAsnByName[asn_name] = asn_new_id
                    asn_id = asn_new_id
                    for cidr,v in reservedNetworks.items():
                        if cidr.find(":") < 0:
                            CIDRInfo = CIDRv4Detail(cidr)
                            new_networks += 1
                        elif with_ipv6 == True:
                            CIDRInfo = CIDRv6Detail(cidr)
                            new_networks += 1
                        else:
                            continue
                        for key,val in v.items():
                            country_code = key
                            first_ip2int = CIDRInfo.first_ip2int
                            last_ip2int = CIDRInfo.last_ip2int
                            dictGeoAsn[first_ip2int] = {'asn_id':asn_id,
                                                        'asn_name':asn_name,
                                                        'asn_cidr':cidr,
                                                        'last_ip':last_ip2int
                                                    }
                    log(f"- Added {str(new_networks)} private/reserved networks... done! {timer(elapsed())}")
                except Exception as ERR:
                    logError("%s"%(str(ERR)))
                    return 1
            with elapsed_timer() as elapsed_debug:
                dictGeoAsn = dict(sorted(dictGeoAsn.items(),key=lambda x:int(x[0]), reverse=False))
                listFirstIPASN = [int(item) for item in list(dictGeoAsn.keys())]
                # log(f"- Sorting dictGeoAsn by First IP... done! {timer(elapsed_debug())}")
            with elapsed_timer() as elapsed_debug:
                ipCounter_v4, ipCounter_v6 = 0, 0
                for key,val in dictGeoAsn.items():
                    if val['last_ip'] <= numIPsv4[0]:
                        ipCounter_v4 += numIPsv4[int(val['asn_cidr'].split("/")[1])]
                    else:
                        ipCounter_v6 += numIPsv6[int(val['asn_cidr'].split("/")[1])]
                percentage_v4 = (ipCounter_v4 * 100) / numIPsv4[0]
                timer_string = timer(elapsed_debug())
                log(f"- ASN IPv4 coverage {'%.2f%%'%(percentage_v4)} {timer_string}")
                if with_ipv6 == True:
                    percentage_v6 = (ipCounter_v6 * 100) / numIPsv6[0]
                    log(f"- ASN IPv6 coverage {'%.2f%%'%(percentage_v6)} {timer_string}")
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("dictGeoAsn.json","w") as f:
                        json.dump(dictGeoAsn,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictGeoAsn.json with {len(dictGeoAsn.keys())} items... done! {timer(elapsed_debug())}")
                with elapsed_timer() as elapsed_debug:
                    with open("dictNamesAsnByName.json","w") as f:
                        json.dump(dictNamesAsnByName,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictNamesAsnByName.json with {len(dictNamesAsnByName.keys())} items... done! {timer(elapsed_debug())}")
                with elapsed_timer() as elapsed_debug:
                    dictNamesAsnByID = {value: key for key, value in dictNamesAsnByName.items()}
                    with open("dictNamesAsnByID.json","w") as f:
                        json.dump(dictNamesAsnByID,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictNamesAsnByID.json with {len(dictNamesAsnByID.keys())} items... done! {timer(elapsed_debug())}")
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

         #####     #######    #     #    #     #    #######    ######     #     #
        #     #    #     #    #     #    ##    #       #       #     #     #   #
        #          #     #    #     #    # #   #       #       #     #      # #
        #          #     #    #     #    #  #  #       #       ######        #
        #          #     #    #     #    #   # #       #       #   #         #
        #     #    #     #    #     #    #    ##       #       #    #        #
         #####     #######     #####     #     #       #       #     #       #

        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        
        dictGeoCountry = {}
        dictCountryByISOCode = {}
        dictCountryByGeonameID = {}
        if country_dir != "" and city_dir == "":
            logMemory(f"%.2f MiB"%(get_mem_usage()))
            log(f"- Starting read lines from CSV file {MM_COUNTRY_LOCATIONS_FILENAME.replace('XX',language)}")
            with elapsed_timer() as elapsed:
                try:
                    counter = 0
                    with io.open(os.path.join(country_dir,MM_COUNTRY_LOCATIONS_FILENAME.replace("XX",language)), mode="rt",encoding="utf-8",) as f:
                        next(f)  # skip the first line (the CSV's header)
                        reader = csv.reader(f, delimiter=',', quotechar='"')
                        for fields in reader:
                            try:
                                counter += 1
                                geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,is_in_european_union = map(str.strip, fields)
                                if country_iso_code == "":
                                    country_iso_code, country_name = continent_code, continent_name
                                    if country_iso_code == "AS":
                                        country_iso_code = "ASIA"
                                dictCountryByGeonameID[geoname_id] = country_iso_code
                                dictCountryByISOCode[country_iso_code] = country_name
                            except Exception as ERR:
                                logError(f"Failed to process line {fields} - {str(ERR)}")
                                continue
                    log(f"- Read {counter} lines from file {MM_COUNTRY_LOCATIONS_FILENAME.replace('XX',language)}... done! {timer(elapsed())}")
                except Exception as ERR:
                    logError(f"Failed at country location read file %s"%(str(ERR)))
                    return 1
            try:
                with elapsed_timer() as elapsed:
                    new_networks = 0
                    geoname_id = int(list(dictCountryByGeonameID.keys())[-1])
                    for cidr,v in reservedNetworks.items():
                        geoname_id += 1
                        for code,desc in v.items():
                            if cidr.find(":") < 0:
                                new_networks += 1
                            elif with_ipv6 == True:
                                new_networks += 1
                            else:
                                continue
                            dictCountryByGeonameID[geoname_id] = code
                            dictCountryByISOCode[code] = desc
                log(f"- Added {str(new_networks)} private/reserved networks... done! {timer(elapsed())}")
                dictCountryByISOCode["99"] = '<not found in database>'
                dictCountryByGeonameID[geoname_id+1] = "99"
                log(f"- Added 1 location '99':'<not found in database>'... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed at country location add new networks %s"%(str(ERR)))
                return 1        
            with elapsed_timer() as elapsed_debug:
                dictCountryByISOCode = dict(sorted(dictCountryByISOCode.items(),key=lambda x:x[0], reverse=False))
                # log(f"- Sorting dictCountryByISOCode by ISO Country Code... done! {timer(elapsed_debug())}")
            with elapsed_timer() as elapsed_debug:
                dictCountryByGeonameID = dict(sorted(dictCountryByGeonameID.items(),key=lambda x:int(x[0]), reverse=False))
                # log(f"- Sorting dictCountryByGeonameID by GeonameID... done! {timer(elapsed_debug())}")
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("dictCountryByGeonameID.json","w") as f:
                        json.dump(dictCountryByGeonameID,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictCountryByGeonameID.json with {len(dictCountryByGeonameID.keys())} items... done! {timer(elapsed_debug())}")
                    with open("dictCountryByISOCode.json","w") as f:
                        json.dump(dictCountryByISOCode,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictCountryByISOCode.json with {len(dictCountryByISOCode.keys())} items... done! {timer(elapsed_debug())}")
            file_list = [MM_COUNTRY_BLOCKS_IPV4_FILENAME]
            if with_ipv6 == True:
                file_list.append(MM_COUNTRY_BLOCKS_IPV6_FILENAME)
            for FILE in file_list:
                is_IPV6 = FILE.find("v6") >= 0
                log(f"- Starting read lines from CSV file {FILE}")
                counter = 0
                with elapsed_timer() as elapsed:
                    try:
                        with io.open(os.path.join(country_dir,FILE.replace("XX",language)), mode="rt",encoding="utf-8") as f:
                            next(f)  # skip the first line (the CSV's header)
                            reader = csv.reader(f, delimiter=',', quotechar='"')
                            for fields in reader:
                                try:
                                    counter += 1
                                    try:
                                        cidr, geoname_id, registered_country_id, represented_country_id, \
                                            is_anonymous_proxy, is_satellite_provider,*_any_other_field  = map(str.strip, fields)
                                        if is_IPV6:
                                            CIDRInfo = CIDRv6Detail(cidr)
                                        else:
                                            CIDRInfo = CIDRv4Detail(cidr)
                                        if registered_country_id == "":
                                            registered_country_id = geoname_id
                                        if geoname_id == "":    
                                            geoname_id = registered_country_id
                                        if geoname_id == "":
                                            country_code = "XX"
                                        else:
                                            country_code = dictCountryByGeonameID[geoname_id]
                                        if country_code == "":
                                            country_code = "XX"
                                        firstIP = CIDRInfo.first_ip2int
                                        lastIP = CIDRInfo.last_ip2int
                                        dictGeoCountry[firstIP] = {'cidr':cidr,
                                                                'country_code':country_code,
                                                                'last_ip':lastIP,
                                                                'geoname_id':geoname_id,
                                                                #    'registered_country_id':registered_country_id, 
                                                                #    'represented_country_id':represented_country_id,
                                                                #    'is_anonymous_proxy':bool(int(is_anonymous_proxy)),
                                                                #    'is_satellite_provider': bool(int(is_satellite_provider)),
                                                                }
                                    except Exception as ERR:
                                        logError(f"Failed to process line {fields} - {str(ERR)}")
                                    if counter % 10000 == 0:
                                        # break
                                        log(f"\r> Lines read: {counter}",end="")
                                except Exception as ERR:
                                    logError("Failed at country blocks loop %s"%(str(ERR)))
                                    continue
                        log(f"\r- Lines read: {counter} done! {timer(elapsed())}")
                    except Exception as ERR:
                        logError("Failed country cidr readline %s"%(str(ERR)))
                        return 1 
            with elapsed_timer() as elapsed:
                try:
                    if len(listFirstIPASN) > 0:
                        asn_id = asn_new_id
                        asn_name = 'IANA.ORG'
                    else:
                        asn_id = 0
                        asn_name = ''
                    new_networks = 0
                    for cidr,v in reservedNetworks.items():
                        if cidr.find(":") < 0:
                            CIDRInfo = CIDRv4Detail(cidr)
                            new_networks += 1
                        elif with_ipv6 == True:
                            CIDRInfo = CIDRv6Detail(cidr)
                            new_networks += 1
                        else:
                            continue
                        for key,value in v.items():
                            # if CIDRInfo.is_ipv6 == True and with_ipv6 == False:
                            #     new_networks -= 1
                            #     continue
                            country_code = key
                            first_ip2int = CIDRInfo.first_ip2int
                            dictGeoCountry[first_ip2int] = {'cidr':cidr,
                                                            'country_code':country_code,
                                                            'last_ip':CIDRInfo.last_ip2int,
                                                            'geoname_id':0,
                                                        }
                    log(f"- Added {str(new_networks)} private/reserved networks... done! {timer(elapsed())}")
                except Exception as ERR:
                    logError("%s"%(str(ERR)))
                    return 1
            with elapsed_timer() as elapsed_debug:
                dictGeoCountry = dict(sorted(dictGeoCountry.items(),key=lambda x:int(x[0]), reverse=False))
                # log(f"- Sorting dictGeoCountry by First IP... done! {timer(elapsed_debug())}")
            with elapsed_timer() as elapsed_debug:
                ipCounter_v4, ipCounter_v6 = 0, 0
                for key,val in dictGeoCountry.items():
                    if val['last_ip'] <= numIPsv4[0]:
                        ipCounter_v4 += numIPsv4[int(val['cidr'].split("/")[1])]
                    else:
                        ipCounter_v6 += numIPsv6[int(val['cidr'].split("/")[1])]
                percentage_v4 = (ipCounter_v4 * 100) / numIPsv4[0]
                timer_string = timer(elapsed_debug())
                log(f"- Country IPv4 coverage {'%.2f%%'%(percentage_v4)} {timer_string}")
                if with_ipv6 == True:
                    percentage_v6 = (ipCounter_v6 * 100) / numIPsv6[0]
                    log(f"- Country IPv6 coverage {'%.2f%%'%(percentage_v6)} {timer_string}")
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("dictGeoCountry.json","w") as f:
                        json.dump(dictGeoCountry,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictGeoCountry.json with {len(dictGeoCountry.keys())} items... done! {timer(elapsed_debug())}")
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            
          #####     ###    #######    #     #
         #     #     #        #        #   #
         #           #        #         # #
         #           #        #          #
         #           #        #          #
         #     #     #        #          #
          #####     ###       #          #

        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        dictGeoCity = {}
        dictNamesCityByGeonameID = {}
        if city_dir != "" and country_dir == "":
            logMemory(f"%.2f MiB"%(get_mem_usage()))
            dictNamesCityByGeonameID['0'] = {'city_name':'<unknown>',
                                                    'city_new_id':0,
                                                    'subdivision_1_iso_code':'',
                                                    'subdivision_1_name':'',
                                                    'subdivision_2_iso_code':'',
                                                    'subdivision_2_name':'',
                                                    'country_iso_code':'99',
                                                    }
            dictCountryByISOCode = {}
            dictCountryByGeonameID = {}
            city_new_id = 0
            log(f"- Starting read lines from CSV file {MM_CITY_LOCATIONS_FILENAME.replace('XX',language)}")
            with elapsed_timer() as elapsed:
                try:
                    counter = 0
                    with io.open(os.path.join(city_dir,MM_CITY_LOCATIONS_FILENAME.replace("XX",language)), mode="rt",encoding="utf-8",) as f:
                        next(f)  # skip the first line (the CSV's header)
                        reader = csv.reader(f, delimiter=',', quotechar='"')
                        for fields in reader:
                            try:
                                counter += 1
                                geoname_id,locale_code,continent_code,continent_name,country_iso_code,country_name,subdivision_1_iso_code, \
                                    subdivision_1_name,subdivision_2_iso_code,subdivision_2_name,city_name,metro_code,time_zone, \
                                    is_in_european_union = map(str.strip, fields)
                                if country_iso_code == "":
                                    country_iso_code, country_name = continent_code, continent_name
                                    if country_iso_code == "AS":
                                        country_iso_code = "ASIA"
                                city_new_id += 1
                                # district_code = f"{subdivision_1_iso_code}" if subdivision_1_iso_code and len(subdivision_1_iso_code) == 2 and not subdivision_1_iso_code.isdigit() else ""
                                # district_name = f"{subdivision_1_name}" if subdivision_1_name else ""
                                # if not city_name:
                                #     city_name = district_name if subdivision_1_name else district_code[1:]
                                # else:
                                #     city_name += ", "+district_name
                                # if subdivision_2_name:
                                #     city_name += ", "+subdivision_2_name
                                dictNamesCityByGeonameID[geoname_id] = {'city_name':city_name,
                                                                        'city_new_id':city_new_id,
                                                                        'subdivision_1_iso_code':subdivision_1_iso_code,
                                                                        'subdivision_1_name':subdivision_1_name,
                                                                        'subdivision_2_iso_code':subdivision_2_iso_code,
                                                                        'subdivision_2_name':subdivision_2_name,
                                                                        'country_iso_code':country_iso_code,
                                                                        }
                                dictCountryByGeonameID[geoname_id] = country_iso_code
                                dictCountryByISOCode[country_iso_code] = country_name
                            except Exception as ERR:
                                logError(f"Failed to process line {fields} - {str(ERR)}")
                                continue
                    log(f"- Read {counter} lines from file {MM_CITY_LOCATIONS_FILENAME.replace('XX',language)}... done! {timer(elapsed())}")
                except Exception as ERR:
                    logError(f"Failed at city location read file %s"%(str(ERR)))
                    return 1
            try:
                with elapsed_timer() as elapsed:
                    new_networks = 0
                    geoname_id = int(list(dictCountryByGeonameID.keys())[-1])
                    for cidr,v in reservedNetworks.items():
                        geoname_id += 1
                        for code,desc in v.items():
                            if cidr.find(":") < 0:
                                new_networks += 1
                            elif with_ipv6 == True:
                                new_networks += 1
                            else:
                                continue
                            city_new_id += 1
                            dictNamesCityByGeonameID[geoname_id] = {'city_name':"",
                                                                    'city_new_id':city_new_id,
                                                                    'subdivision_1_iso_code':"",
                                                                    'subdivision_1_name':"",
                                                                    'subdivision_2_iso_code':"",
                                                                    'subdivision_2_name':"",
                                                                    'country_iso_code':code,
                                                                    }
                            dictCountryByGeonameID[geoname_id] = code                            
                            dictCountryByISOCode[code] = desc
                log(f"- Added {str(new_networks)} private/reserved networks... done! {timer(elapsed())}")
                dictCountryByISOCode["99"] = '<not found in database>'
                dictCountryByGeonameID[geoname_id+1] = "99"
                city_new_id += 1
                dictNamesCityByGeonameID[geoname_id+1] = {  'city_name':"<not found in database>",
                                                            'city_new_id':city_new_id,
                                                            'subdivision_1_iso_code':"",
                                                            'subdivision_1_name':"",
                                                            'subdivision_2_iso_code':"",
                                                            'subdivision_2_name':"",
                                                            'country_iso_code':"99",
                                                       }
                log(f"- Added 1 location '99':'<not found in database>'... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed at country location add new networks %s"%(str(ERR)))
                return 1        
            with elapsed_timer() as elapsed_debug:
                dictGeonameIDByISOCode = {val:key for key,val in dictCountryByGeonameID.items()}
                dictGeonameIDByISOCode = dict(sorted(dictGeonameIDByISOCode.items(),key=lambda x:x[0], reverse=False))
                # log(f"- Sorting dictGeonameIDByISOCode by GeonameID... done! {timer(elapsed_debug())}")
            with elapsed_timer() as elapsed_debug:
                dictNamesCityByGeonameID = dict(sorted(dictNamesCityByGeonameID.items(),key=lambda x:int(x[0]), reverse=False))
                # log(f"- Sorting dictNamesCityByGeonameID by GeonameID... done! {timer(elapsed_debug())}")
            with elapsed_timer() as elapsed_debug:
                dictCountryByISOCode = dict(sorted(dictCountryByISOCode.items(),key=lambda x:x[0], reverse=False))
                # log(f"- Sorting dictCountryByISOCode by ISO Country Code... done! {timer(elapsed_debug())}")
            with elapsed_timer() as elapsed_debug:
                dictCountryByGeonameID = dict(sorted(dictCountryByGeonameID.items(),key=lambda x:int(x[0]), reverse=False))
                # log(f"- Sorting dictCountryByGeonameID by GeonameID... done! {timer(elapsed_debug())}")
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("dictGeonameIDByISOCode.json","w") as f:
                        json.dump(dictGeonameIDByISOCode,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictGeonameIDByISOCode.json with {len(dictGeonameIDByISOCode.keys())} items... done! {timer(elapsed_debug())}")
                with elapsed_timer() as elapsed_debug:
                    with open("dictNamesCityByGeonameID.json","w") as f:
                        json.dump(dictNamesCityByGeonameID,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictNamesCityByGeonameID.json with {len(dictNamesCityByGeonameID.keys())} items... done! {timer(elapsed_debug())}")
                with elapsed_timer() as elapsed_debug:
                    with open("dictCountryByGeonameID.json","w") as f:
                        json.dump(dictCountryByGeonameID,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictCountryByGeonameID.json with {len(dictCountryByGeonameID.keys())} items... done! {timer(elapsed_debug())}")
                with elapsed_timer() as elapsed_debug:
                    with open("dictCountryByISOCode.json","w") as f:
                        json.dump(dictCountryByISOCode,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictCountryByISOCode.json with {len(dictCountryByISOCode.keys())} items... done! {timer(elapsed_debug())}")               

            file_list = [MM_CITY_BLOCKS_IPV4_FILENAME]
            if with_ipv6 == True:
                file_list.append(MM_CITY_BLOCKS_IPV6_FILENAME)
            for FILE in file_list:
                is_IPV6 = FILE.find("v6") >= 0
                log(f"- Starting read lines from CSV file {FILE}")
                counter = 0
                with elapsed_timer() as elapsed:
                    try:
                        with io.open(os.path.join(city_dir,FILE.replace("XX",language)), mode="rt",encoding="utf-8") as f:
                            next(f)  # skip the first line (the CSV's header)
                            reader = csv.reader(f, delimiter=',', quotechar='"')
                            for fields in reader:
                                try:
                                    counter += 1
                                    try:
                                        cidr,geoname_id,registered_country_geoname_id,represented_country_geoname_id,is_anonymous_proxy,\
                                            is_satellite_provider,postal_code,latitude,longitude,accuracy_radius,*_any_other_field = map(str.strip, fields)
                                        if is_IPV6:
                                            CIDRInfo = CIDRv6Detail(cidr)
                                        else:
                                            CIDRInfo = CIDRv4Detail(cidr)
                                        if registered_country_geoname_id == "":
                                            registered_country_geoname_id = geoname_id
                                        if geoname_id == "":    
                                            geoname_id = registered_country_geoname_id
                                        if geoname_id == "":
                                            country_code = "XX"
                                        else:
                                            country_code = dictCountryByGeonameID[geoname_id]
                                        if country_code == "":
                                            country_code = "XX"
                                        firstIP = CIDRInfo.first_ip2int
                                        lastIP = CIDRInfo.last_ip2int
                                        city_new_id = dictNamesCityByGeonameID[geoname_id]['city_new_id']
                                        dictGeoCity[firstIP] = {'cidr':cidr,
                                                                'country_code':country_code,
                                                                'last_ip':lastIP,
                                                                'geoname_id':geoname_id,
                                                                'city_new_id':city_new_id,
                                                                #    'registered_country_id':registered_country_id, 
                                                                #    'represented_country_id':represented_country_id,
                                                                #    'is_anonymous_proxy':bool(int(is_anonymous_proxy)),
                                                                #    'is_satellite_provider': bool(int(is_satellite_provider)),
                                                                }
                                    except Exception as ERR:
                                        logError(f"Failed to process line {fields} - {str(ERR)}")
                                    if counter % 30000 == 0:
                                        # break
                                        log(f"\r> Lines read: {counter}",end="")
                                except Exception as ERR:
                                    logError("Failed at city blocks loop %s"%(str(ERR)))
                                    continue
                        log(f"\r- Lines read: {counter} done! {timer(elapsed())}")
                    except Exception as ERR:
                        logError("Failed country cidr readline %s"%(str(ERR)))
                        return 1 
            with elapsed_timer() as elapsed:
                try:
                    if len(listFirstIPASN) > 0:
                        asn_id = asn_new_id
                        asn_name = 'IANA.ORG'
                    else:
                        asn_id = 0
                        asn_name = ''
                    new_networks = 0
                    for cidr,v in reservedNetworks.items():
                        if cidr.find(":") < 0:
                            CIDRInfo = CIDRv4Detail(cidr)
                            new_networks += 1
                        elif with_ipv6 == True:
                            CIDRInfo = CIDRv6Detail(cidr)
                            new_networks += 1
                        else:
                            continue
                        for key,value in v.items():
                            # if CIDRInfo.is_ipv6 == True and with_ipv6 == False:
                            #     new_networks -= 1
                            #     continue
                            country_code = key
                            first_ip2int = CIDRInfo.first_ip2int
                            geoname_id = dictGeonameIDByISOCode[country_code]
                            city_new_id = dictNamesCityByGeonameID[geoname_id]['city_new_id']
                            dictGeoCity[first_ip2int] = {'cidr':cidr,
                                                            'country_code':country_code,
                                                            'last_ip':CIDRInfo.last_ip2int,
                                                            'geoname_id':geoname_id,
                                                            'city_new_id':city_new_id,
                                                        }
                    log(f"- Added {str(new_networks)} private/reserved networks... done! {timer(elapsed())}")
                except Exception as ERR:
                    logError("%s"%(str(ERR)))
                    return 1
            with elapsed_timer() as elapsed_debug:
                dictGeoCity = dict(sorted(dictGeoCity.items(),key=lambda x:int(x[0]), reverse=False))
                # log(f"- Sorting dictGeoCity by First IP... done! {timer(elapsed_debug())}")
            with elapsed_timer() as elapsed_debug:
                ipCounter_v4, ipCounter_v6 = 0, 0
                for key,val in dictGeoCity.items():
                    if val['last_ip'] <= numIPsv4[0]:
                        ipCounter_v4 += numIPsv4[int(val['cidr'].split("/")[1])]
                    else:
                        ipCounter_v6 += numIPsv6[int(val['cidr'].split("/")[1])]
                percentage_v4 = (ipCounter_v4 * 100) / numIPsv4[0]
                timer_string = timer(elapsed_debug())
                log(f"- City IPv4 coverage {'%.2f%%'%(percentage_v4)} {timer_string}")
                if with_ipv6 == True:
                    percentage_v6 = (ipCounter_v6 * 100) / numIPsv6[0]
                    log(f"- City IPv6 coverage {'%.2f%%'%(percentage_v6)} {timer_string}")
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("dictGeoCity.json","w") as f:
                        json.dump(dictGeoCity,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"Saving debug file dictGeoCity.json with {len(dictGeoCity.keys())} items... done! {timer(elapsed_debug())}")

        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try:
                listNamesCountry = [f"{key}:{val}" for key,val in dictCountryByISOCode.items()]
                listCountryISOCodes = [f"{key}" for key,val in dictCountryByISOCode.items()]
                log(f"- List Country Names with {len(listNamesCountry)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listNamesCountry %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("listNamesCountry.txt","w") as f:
                        f.writelines(str("\n".join(listNamesCountry)))
                    logDebug(f"Saving listNamesCountry.txt with {len(listNamesCountry)} items... done! {timer(elapsed_debug())}")
            del dictCountryByISOCode
        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try:
                listNamesAsn = [f"{key}" for key,val in dictNamesAsnByName.items()]
                log(f"- List ASN Names with {len(listNamesAsn)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listNamesAsn %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("listNamesAsn.txt","w") as f:
                        f.writelines(str("\n".join(listNamesAsn)))
                    logDebug(f"Saving listNamesAsn.txt with {len(listNamesAsn)} items... done! {timer(elapsed_debug())}")
            del dictNamesAsnByName
        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try:
                listNamesCity = [f"{val['country_iso_code']}:{val['city_name']}|{val['subdivision_1_iso_code']}|{val['subdivision_1_name']}|{val['subdivision_2_iso_code']}|{val['subdivision_2_name']}" for key,val in dictNamesCityByGeonameID.items()]
                log(f"- List City Names with {len(listNamesCity)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listNamesCity %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("listNamesCity.txt","w") as f:
                        f.writelines(str("\n".join(listNamesCity)))
                    logDebug(f"Saving listNamesCity.txt with {len(listNamesCity)} items... done! {timer(elapsed_debug())}")
            del dictNamesCityByGeonameID
        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try:                
                _listFirstIP = [int(key) for key,val in dictGeoCity.items()] if city_dir != "" else [int(key) for key,val in dictGeoCountry.items()]
                listFirstIP = list(split_list(_listFirstIP,LIST_SLICE_SIZE))
                totalNetworks = len(_listFirstIP)
                log(f"- List First IP with {len(_listFirstIP)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listFirstIP %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("listFirstIP.json","w") as f:
                        json.dump(listFirstIP,f,indent=2,ensure_ascii=False,sort_keys=False)
                    logDebug(f"Saving listFirstIP.json with {len(_listFirstIP)} items... done! {timer(elapsed_debug())}")
            del _listFirstIP
        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try:                
                _listFirstIPASN = [int(key) for key,val in dictGeoAsn.items()] if asn_dir != "" else []
                listFirstIPASN = list(split_list(_listFirstIPASN,LIST_SLICE_SIZE))
                log(f"- List ASN First IP with {len(_listFirstIPASN)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listFirstIPASN %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("listFirstIPASN.json","w") as f:
                        json.dump(listFirstIPASN,f,indent=2,ensure_ascii=False,sort_keys=False)
                    logDebug(f"Saving listFirstIPASN.json with {len(_listFirstIPASN)} items... done! {timer(elapsed_debug())}")
            del _listFirstIPASN
        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try:                
                _listIDCountryCodes = [int(listCountryISOCodes.index(val['country_code'])) for key,val in dictGeoCity.items()] if city_dir != "" else [listCountryISOCodes.index(val['country_code']) for key,val in dictGeoCountry.items()]
                listIDCountryCodes = list(split_list(_listIDCountryCodes,LIST_SLICE_SIZE))
                log(f"- List Country Codes IDs with {len(_listIDCountryCodes)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listIDCountryCodes %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("listIDCountryCodes.json","w") as f:
                        json.dump(listIDCountryCodes,f,indent=2,ensure_ascii=False,sort_keys=False)
                    logDebug(f"Saving listIDCountryCodes.json with {len(_listIDCountryCodes)} items... done! {timer(elapsed_debug())}")
            del _listIDCountryCodes
        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try: 
                _listIDASN = [int(val['asn_id']) for key,val in dictGeoAsn.items()] if asn_dir != "" else []
                listIDASN = list(split_list(_listIDASN,LIST_SLICE_SIZE))
                log(f"- List ASN IDs with {len(_listIDASN)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listIDASN %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("listIDASN.json","w") as f:
                        json.dump(listIDASN,f,indent=2,ensure_ascii=False,sort_keys=False)
                    logDebug(f"Saving listIDASN.json with {len(_listIDASN)} items... done! {timer(elapsed_debug())}")
            del _listIDASN
        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try:                
                _listIDCity = [val['city_new_id'] for key,val in dictGeoCity.items()] if city_dir != "" else []
                listIDCity = list(split_list(_listIDCity,LIST_SLICE_SIZE))
                log(f"- List City IDs with {len(_listIDCity)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listIDCity %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("listIDCity.json","w") as f:
                        json.dump(listIDCity,f,indent=2,ensure_ascii=False,sort_keys=False)
                    logDebug(f"Saving listIDCity.json with {len(_listIDCity)} items... done! {timer(elapsed_debug())}")
            del _listIDCity
        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try:                
                _listNetlengthASN = [int(val['asn_cidr'].split("/")[-1]) for key,val in dictGeoAsn.items()] if asn_dir != "" else []
                listNetlengthASN = list(split_list(_listNetlengthASN,LIST_SLICE_SIZE))
                log(f"- List Network Length ASN with {len(_listNetlengthASN)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listNetlengthASN %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("listNetlengthASN.json","w") as f:
                        json.dump(listNetlengthASN,f,indent=2,ensure_ascii=False,sort_keys=False)
                    logDebug(f"Saving listNetlengthASN.json with {len(_listNetlengthASN)} items... done! {timer(elapsed_debug())}")
            del _listNetlengthASN
        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try:                
                _listNetlength = [int(val['cidr'].split("/")[-1]) for key,val in dictGeoCity.items()] if city_dir != "" else [int(val['cidr'].split("/")[-1]) for key,val in dictGeoCountry.items()]
                listNetlength = list(split_list(_listNetlength,LIST_SLICE_SIZE))
                log(f"- List Network Length with {len(_listNetlength)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listNetlength %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("listNetlength.json","w") as f:
                        json.dump(listNetlength,f,indent=2,ensure_ascii=False,sort_keys=False)
                    logDebug(f"Saving listNetlength.json with {len(_listNetlength)} items... done! {timer(elapsed_debug())}")
            del _listNetlength
            try:del dictGeoCity
            except: pass
            try:del dictGeoCountry
            except: pass
        logMemory(f"%.2f MiB"%(get_mem_usage()))
        with elapsed_timer() as elapsed:
            try:                
                mainIndex, mainIndexASN = [], []
                for item in listFirstIP:
                    mainIndex.append(item[0])
                for item in listFirstIPASN:
                    mainIndexASN.append(item[0])
                log(f"- Creating Main Index with {len(mainIndex)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create mainIndex %s"%(str(ERR)))
                return 1
            if debug == True:
                with elapsed_timer() as elapsed_debug:
                    with open("mainIndex.json","w") as f:
                        json.dump(mainIndex,f,indent=2,ensure_ascii=False,sort_keys=False)
                    logDebug(f"Saving mainIndex.json with {len(mainIndex)} items... done! {timer(elapsed_debug())}")

        with elapsed_timer() as elapsed:
            log(f"- Creating pickle database...")
            source_info = {
                'info':source_info,
                'country':bool(country_dir != ""),
                'city':bool(city_dir != ""),
                'asn':bool(asn_dir != ""),
                'ipv6':with_ipv6,
            }
            
            ##──── COUNTRY ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            if (country_dir != "") and (city_dir == "") and (asn_dir == ""):
                mainList = [mainIndex,listNamesCountry,listFirstIP,listIDCountryCodes,listNetlength]
            ##──── COUNTRY + ASN ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
            elif (country_dir != "") and (city_dir == "") and (asn_dir != ""):
                mainList = [mainIndex,mainIndexASN,listNamesCountry,listNamesAsn,listFirstIP,
                            listFirstIPASN,listIDCountryCodes,listIDASN,listNetlength,listNetlengthASN]
            ##──── CITY ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            elif (country_dir == "") and (city_dir != "") and (asn_dir == ""):
                mainList = [mainIndex,listNamesCountry,listNamesCity,listFirstIP,listIDCity,listNetlength]
            ##──── CITY + ASN ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            elif (country_dir == "") and (city_dir != "") and (asn_dir != ""):
                mainList = [mainIndex,mainIndexASN,listNamesCountry,listNamesCity,listNamesAsn,
                            listFirstIP,listFirstIPASN,listIDCity,listIDASN,listNetlength,listNetlengthASN]

            database = [ __DAT_VERSION__,  # integer
                        source_info,       # string
                        totalNetworks,     # integer
                        mainList           # list of lists 
            ]

            logMemory(f"%.2f MiB"%(get_mem_usage()))
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        if debug == True:
            with elapsed_timer() as elapsed_debug:
                with open("geoip2fast.dat.json","w") as f:
                    json.dump(database,f,indent=3,sort_keys=False,ensure_ascii=False)            
                logDebug(f"Saving debug file geoip2fast.dat.json... done! {timer(elapsed_debug())}")
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        with elapsed_timer() as elapsed_save_gzip:
            with gzip.GzipFile(filename=os.path.join(output_dir,GEOIP2FAST_DAT_FILENAME_GZ), mode='wb', compresslevel=9) as f:
                pickle.dump(database,f,pickle.HIGHEST_PROTOCOL)
        log(f"- Saved file {os.path.join(output_dir,GEOIP2FAST_DAT_FILENAME_GZ)} {timer(elapsed_save_gzip())}")
        logMemory(f"%.2f MiB"%(get_mem_usage()))
    ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    log(cYellow(f"- ALL DONE!!! {timer(elapsed_total())}"))
    
##################################################################################################################################
##################################################################################################################################

                             ##     ##    ###    #### ##    ##                 
                             ###   ###   ## ##    ##  ###   ##                 
                             #### ####  ##   ##   ##  ####  ##                 
                             ## ### ## ##     ##  ##  ## ## ##                 
                             ##     ## #########  ##  ##  ####                 
                             ##     ## ##     ##  ##  ##   ###                 
             ####### ####### ##     ## ##     ## #### ##    ## ####### ####### 
 
##################################################################################################################################
##################################################################################################################################
#defmain
def main_function():
    global args, _DEBUG
    if '-v' not in sys.argv:
        logVerbose = _log_empty
        
    parser = ArgumentParser(formatter_class=class_argparse_formatter,
                               description=__doc__,
                               allow_abbrev=True,
                               epilog="",
                               add_help=False
                               )
    fileimport = parser.add_argument_group("Mandatory import options")
    # for future use
    fileimport.add_argument("--country-dir",dest='country_dir',action="store",default="",metavar="<directory>",help="Provide the full path of the CSV files GeoLite2-Country-Blocks-IPv4.csv and GeoLite2-Country-Locations-XX.csv files. Only the path of directory. "+cBlue("USE --country-dir OR --city-dir."))
    fileimport.add_argument("--city-dir",dest='city_dir',action="store",metavar="<directory>",default="",help="Provide the full path of the CSV files GeoLite2-City-Blocks-IPv4.csv files. "+cBlue("City data already includes country data."))
    fileimport.add_argument("--output-dir",dest='output_dir',action="store",default="",metavar="<directory>",help="Define the output directory to save the file geoip2fast.dat.gz. Any file with the same name will be renamed. Defalt: current directory.")
    
    optional = parser.add_argument_group("Optional import options")
    optional.add_argument("--asn-dir",dest='asn_dir',action="store",metavar="<directory>",default="",help="Provide the full path of the CSV files GeoLite2-ASN-Blocks-IPv4.csv files. Necessary only if you want to create the dat file with ASN support. ASN data requires --country-dir and/or --city-dir")
    optional.add_argument("--language",dest='language',action="store",default="en",choices=AVAILABLE_LANGUAGES,help="Choose the language of locations that you want to use. Default: en.")
    optional.add_argument("--with-ipv6",dest='withipv6',action="store_true",default=False,help="Include IPv6 network ranges.")
    optional1 = parser.add_argument_group("More options")
    optional1.add_argument('-v',dest="verbose",action='store_true',default=False,help='0|Show useful messages for debugging.')
    optional1.add_argument('-h','--help',action='help',help='0|Show a help message about the allowed commands.')
    optional1.add_argument('--version','-version',action='version',help='0|Show the application version.',version="%s v%s"%(__appid__,__version__))
    # HIDDEN
    optional1.add_argument("--source-info",dest='sourceinfo',action="store",metavar="<text>",default="",help=SUPPRESS)
    optional1.add_argument('--debug',dest="debug",action='store_true',default=False,help=SUPPRESS)

    ##────── do the parse ───────────────────────────────────────────────────────────────────────────────────────────────────
    args = parser.parse_args()
    ##────── Se não houve subcomando, exiba o help ─────────────────────────────────────────────────────────────────────────

    if (bool(args.country_dir != "") + bool(args.city_dir != "") != 1):
        parser.print_help()
        print(cRed("\nERROR: --country-dir or --city-dir are mandatory and cannot be used together. City option already includes country information.\n"))
        sys.exit(0)
        
    if (bool(args.output_dir == "")):
        parser.print_help()
        print(cRed("\nERROR: --output-dir is mandatory.\n"))
        sys.exit(0)
        
    with geoip2dat():
        sys.exit(run(args.country_dir,args.asn_dir,args.city_dir,args.output_dir,args.language,args.sourceinfo,args.debug,args.withipv6))
    
if __name__ == "__main__":
    sys.exit(main_function())   
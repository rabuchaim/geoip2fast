#!/usr/bin/env python3
# encoding: utf-8
# -*- coding: utf-8 -*-
"""
GeoIP2Dat v1.1.11 - DAT file update for GeoIP2Fast
"""
"""
Author: Ricardo Abuchaim - ricardoabuchaim@gmail.com
        https://github.com/rabuchaim/geoip2fast/

License: MIT
"""
__appid__   = "GeoIP2Dat"
__version__ = "1.1.11"

import sys, os, gzip, pickle, io, socket, struct, json, hashlib, time
from datetime import datetime as dt
from binascii import unhexlify
from argparse import ArgumentParser, HelpFormatter, SUPPRESS
from contextlib import contextmanager
from timeit import default_timer
from pprint import pprint as pp
from bisect import bisect

##──── URL TO DOWNLOAD CSV FILES FROM MAXMIND (FOR FUTURE VERSIONS) ───────────────────────────────────────────────────────────────────────────────────
MM_URL_COUNTRY  = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip"
MM_URL_CITY     = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip"
MM_URL_ASN      = "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip"
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

LIST_SLICE_SIZE                 = 5000
##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
AVAILABLE_LANGUAGES     = ['de','en','es','fr','ja','pt-BR','ru','zh-CN']

__DAT_VERSION__         = 110
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
    "fd00::/8":          {"15":"Reserved for Unique Local Addresses"}
    }

##──── IP MANIPULATION FUNCTIONS ─────────────────────────────────────────────────────────────────────────────────────────────────
ipv4_to_int = lambda ipv4_address: struct.unpack('!I', socket.inet_aton(ipv4_address))[0]
int_to_ipv4 = lambda iplong: socket.inet_ntoa(struct.pack('!I', iplong))
ipv6_to_int = lambda ipv6_address: int.from_bytes(socket.inet_pton(socket.AF_INET6, ipv6_address), byteorder='big')
int_to_ipv6 = lambda iplong: socket.inet_ntop(socket.AF_INET6, unhexlify(hex(iplong)[2:].zfill(32)))
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

def json_default_formatter(o):
    import datetime
    if isinstance(o, (datetime.date, datetime.datetime)):
        return o.__str__

##──── RETURN A MD5SUM HASH OF A STRING ────────────────────────────────────────────────────────────────────────────────────────
def get_md5(stringToHash=""):
    stringToHash = f"{str(stringToHash)}".encode()
    resultMd5 = hashlib.md5(stringToHash)
    return resultMd5.hexdigest()

##──── CLASS TO INTERCEPT INIT, ENTER and EXIT ───────────────────────────────────────────────────────────────────────────────────
class geoip2dat():
    def __init__(self):
        log(letter_repeat(">",terminalWidth))
        log(f">>>>> STARTING {__appid__} v{__version__}")
        log(letter_repeat(">",terminalWidth))
    def __enter__(self):
        pass        
    def __exit__(self,type,value,traceback):
        log(letter_repeat("<",terminalWidth))
        log(f"<<<<< EXITING {__appid__} PROCESS")
        log(letter_repeat("<",terminalWidth))
    def __run__(self,args):
        run()

##──── CLASS FOR ARGUMENT PARSER ─────────────────────────────────────────────────────────────────────────────────────────────────
class class_argparse_formatter(HelpFormatter):
    my_max_help_position = 30
    try:
        ttyRows, ttyCols = os.popen('stty size', 'r').read().split()
    except:
        ttyRows, ttyCols = 30, 150
    ttyRows = int(ttyRows)
    ttyCols = (int(ttyCols) // 4) * 3
    def add_usage(self, usage, actions, groups, prefix=None):
        if prefix is None:
            prefix = 'Sintax: '
        return super(class_argparse_formatter, self).add_usage(usage, actions, groups, prefix)
    def _format_usage(self, usage, actions, groups, prefix):
        return super(class_argparse_formatter, self)._format_usage(usage, actions, groups, prefix)
    def add_text(self, text):
        if text is not SUPPRESS and text is not None:
            if text.startswith('1|'):   # 1| antes do texto dá espaço de 2 linhas
                text = str(text[2:]+"\n\n")
            return super()._add_item(self._format_text, [text])
    def _split_lines(self, text, width): # 0| antes do texto não dá espaço entre linhas
        if text.startswith('0|'):
            return text[2:].splitlines()
        return super()._split_lines(text, width=class_argparse_formatter.ttyCols-class_argparse_formatter.my_max_help_position-5) + ['']
    def _format_action(self, action):
        self._max_help_position = class_argparse_formatter.my_max_help_position
        self._indent_increment = 2
        self._width = class_argparse_formatter.ttyCols
        return super(class_argparse_formatter, self)._format_action(action)
    
##──── Calculate information about a CIDR ────────────────────────────────────────────────────────────────────────────────────────
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
##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
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
##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

class GeoIP2DatError(Exception):
    def __init__(self, message):
        self.message = message
    def __str__(self):
        return self.message

def letter_repeat(letter,times)->str:
    letter1=''
    for N in range (times):
        letter1 = letter1 + letter
    return letter1

##──── Functions to print to stdout ─────────────────────────────────────────────────────────────────────────────────────────────────
def _log_empty(msg,end=""):return
def log(msg,end="\n"):
    print(msg,end=end,flush=True)
def logVerbose(msg,end="\n"):
    print(msg,end=end,flush=True)
def logDebug(msg,end="\n"):
    print(cDarkYellow("[DEBUG] "+msg),end=end,flush=True)
def logError(msg,end="\n"):
    print(cRed("[ERROR] "+msg),end=end,flush=True)
##──── Return date with no spaces to use with filenames ──────────────────────────────────────────────────────────────────────────
def get_date():
    A='%Y%m%d%H%M%S'
    B=dt.now()
    return B.strftime(A)

##──── ANSI colors ───────────────────────────────────────────────────────────────────────────────────────────────────────────────
def cRed(msg): return '\033[91m'+str(msg)+'\033[0m'
def cBlue(msg): return '\033[94m'+str(msg)+'\033[0m'
def cGrey(msg): return '\033[90m'+str(msg)+'\033[0m'
def cWhite(msg): return '\033[97m'+str(msg)+'\033[0m'
def cYellow(msg): return '\033[93m'+str(msg)+'\033[0m'
def cDarkYellow(msg): return '\033[33m'+str(msg)+'\033[0m'

########################################################################################################################
# CLOCK ELAPSED TIME
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

########################################################################################################################
## SPLIT A LIST OR A DICT
def split_list(lista, n):
    for i in range(0, len(lista), n):
        yield lista[i:i + n]

def split_dict(iterable, start, stop):
    from itertools import islice
    return islice(iterable, start, stop)
#################################################################################################################################


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
def run(country_dir,asn_dir,output_dir,language="en",with_ipv6=False,source_info=""):
    global geoip, dictCountryByID
    if source_info == "":
        tempText = ""
        if country_dir != "":
            tempText += 'Country'
        if asn_dir != "":
            tempText += 'ASN'
        if with_ipv6 == True:
            tempText += '-IPv4IPv6'
        else:
            tempText += '-IPv4'
        tempText += "-"+language.replace('-','')+"-"+str(get_date()[:8])
        source_info = DEFAULT_SOURCE_INFO+tempText    
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
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        
        #    #   ##  #  ### ###  #  ###  ##
        #   # # #   # #  #   #  # # # # #
        #   # # #   ###  #   #  # # # #  #
        #   # # #   # #  #   #  # # # #   #
        ###  #   ## # #  #  ###  #  # # ##
    
        log(f"- Starting read lines from CSV file {MM_COUNTRY_LOCATIONS_FILENAME}")
        with elapsed_timer() as elapsed:
            try:
                dictCountryByCode = {}
                dictCountryByID = {}
                counter = 0
                with io.open(os.path.join(country_dir,MM_COUNTRY_LOCATIONS_FILENAME.replace("XX",language)), mode="rt",encoding="utf-8",) as f:
                    next(f)  # skip the first line (the CSV's header)
                    while True:
                        line = f.readline()
                        if not line:
                            break
                        else:
                            try:
                                counter += 1
                                linha = line.replace("\"","").replace("\n","").split(",")
                                geoname_id = linha[0]
                                continent_code = linha[2]
                                continent_name = linha[3]
                                country_iso_code = linha[4]
                                country_name = linha[5]
                                if country_iso_code != "":
                                    dictCountryByID[geoname_id] = country_iso_code
                                    dictCountryByCode[country_iso_code] = country_name
                                else:
                                    dictCountryByID[geoname_id] = continent_code
                                    dictCountryByCode[continent_code] = continent_name                        
                            except Exception as ERR:
                                logError(f"Failed to process line {line} - {str(ERR)}")
                                continue
                log(f"- Read {counter} lines from file {MM_COUNTRY_LOCATIONS_FILENAME.replace('XX',language)}... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed at country location read file %s"%(str(ERR)))
                return 1
        try:
            with elapsed_timer() as elapsed:
                for k,v in reservedNetworks.items():
                    for code,desc in v.items():
                        dictCountryByCode[code] = desc
            log(f"- Added {len(reservedNetworks.keys())} private/reserved networks... done! {timer(elapsed())}")
            dictCountryByCode["XX"] = '<unknown>'
            dictCountryByCode["99"] = '<not found in database>'
            log(f"- Added 1 location '99':'<not found in database>' for future use... done! {timer(elapsed())}")
        except Exception as ERR:
            logError(f"Failed at country location add new networks %s"%(str(ERR)))
            return 1        
        if _DEBUG == True:
            with elapsed_timer() as elapsed_debug:
                with open("geoipLocations.json","w") as f:
                    json.dump(dictCountryByCode,f,indent=3,sort_keys=False,ensure_ascii=False)
                logDebug(f"- Saving debug file geoipLocations.json... done! {timer(elapsed_debug())}")
                        
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        
         #   ## ###
        # # #   # #
        ###  #  # #
        # #   # # #
        # # ##  # #
        
        if asn_dir != "":
            asn_new_id = 0
            geoipASN = {}
            asnNamesDict = {}
            asnNamesDict['<unknown>'] = 0
            file_list = [MM_ASN_BLOCKS_IPV4_FILENAME]
            if with_ipv6 == True:
                file_list.append(MM_ASN_BLOCKS_IPV6_FILENAME)
            for FILE in file_list:
                is_IPV6 = FILE.find("v6") >= 0            
                log(f"- Starting read lines from CSV file {FILE}")
                counter = 0
                with elapsed_timer() as elapsed:
                    try:
                        with io.open(os.path.join(asn_dir,FILE.replace("XX",language)), mode="rt",encoding="utf-8") as f:
                            next(f)  # skip the first line (the CSV's header)
                            while True:
                                try:
                                    counter += 1
                                    line = f.readline()
                                    if not line:
                                        break
                                    else:
                                        try:
                                            LINE = line.split(",")
                                            cidr = LINE[0]
                                            if is_IPV6:
                                                CIDRInfo = CIDRv6Detail(cidr)
                                            else:
                                                CIDRInfo = CIDRv4Detail(cidr)
                                            asn_id = LINE[1]
                                            asn_name = LINE[2].replace("\n","").replace('"','')
                                            firstIP = CIDRInfo.first_ip2int
                                            lastIP = CIDRInfo.last_ip2int
                                            if asnNamesDict.get(asn_name,0) == 0:
                                                asn_new_id += 1
                                                asnNamesDict[asn_name] = asn_new_id
                                                asn_id = asn_new_id
                                            else:
                                                asn_id = asnNamesDict[asn_name]
                                            geoipASN[firstIP] = {'cidr':cidr,'asn_id':asn_id,
                                                                'asn_name':asn_name,
                                                                'last_ip':lastIP}
                                                        #    'geoname_id':geoname_id,
                                                        #    'registered_country_id':registered_country_id, 
                                                        #    'represented_country_id':represented_country_id,
                                                        #    'is_anonymous_proxy':bool(int(is_anonymous_proxy)),
                                                        #    'is_satellite_provider': bool(int(is_satellite_provider)),
                                        except Exception as ERR:
                                            print("Error at \""+LINE+"\" - "+str(ERR))                                    
                                        if counter % 10000 == 0:
                                            # break
                                            log(f"\r> Lines read: {counter}",end="")
                                except Exception as ERR:
                                    logError("Falied at country blocks look %s"%(str(ERR)))
                                    continue
                        log(f"\r- Lines read: {counter} done! {timer(elapsed())}")
                    except Exception as ERR:
                        logError("Failed country cidr readline %s"%(str(ERR)))
                        return 1 
            ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            with elapsed_timer() as elapsed:
                try:
                    asn_new_id += 1
                    asn_name = "IANA.ORG"
                    asnNamesDict[asn_name] = asn_new_id
                    asn_id = asn_new_id
                    for cidr,v in reservedNetworks.items():
                        if cidr.find(":") < 0:
                            CIDRInfo = CIDRv4Detail(cidr)
                        else:
                            CIDRInfo = CIDRv6Detail(cidr)
                        for key,val in v.items():
                            country_code = key
                            if country_code == '14':
                                continue
                            first_ip2int = CIDRInfo.first_ip2int
                            last_ip2int = CIDRInfo.last_ip2int
                            geoipASN[first_ip2int] = {'asn_id':asn_id,'asn_name':asn_name,
                                                    'cidr':cidr,'last_ip':last_ip2int}
                    log(f"- Added {len(reservedNetworks.keys())} private/reserved networks... done! {timer(elapsed())}")
                except Exception as ERR:
                    logError("%s"%(str(ERR)))
                    return 1
            ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
            geoipASN = dict(sorted(geoipASN.items(),key=lambda x:int(x[0]), reverse=False))
            if _DEBUG == True:
                with elapsed_timer() as elapsed_debug:
                    with open("geoipASN.json","w") as f:
                        json.dump(geoipASN,f,indent=3,sort_keys=False,ensure_ascii=False)
                    logDebug(f"- Saving debug file geoipASN.json... done! {timer(elapsed_debug())}")
            with elapsed_timer() as elapsed_debug:
                ipCounter_v4, ipCounter_v6 = 0, 0
                for key,val in geoipASN.items():
                    if val['last_ip'] <= numIPsv4[0]:
                        ipCounter_v4 += numIPsv4[int(val['cidr'].split("/")[1])]
                    else:
                        ipCounter_v6 += numIPsv6[int(val['cidr'].split("/")[1])]
                percentage_v4 = (ipCounter_v4 * 100) / numIPsv4[0]
                log(f"- ASN IPv4 coverage {'%.2f%%'%(percentage_v4)}")
                if with_ipv6 == True:
                    percentage_v6 = (ipCounter_v6 * 100) / numIPsv6[0]
                    log(f"- ASN IPv6 coverage {'%.2f%%'%(percentage_v6)}")
        else:
            asnNamesDict = {}
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        
         ##  #  # # ### ### ##  # #
        #   # # # # # #  #  # # # #
        #   # # # # # #  #  ##   #
        #   # # # # # #  #  # #  #
         ##  #  ### # #  #  # #  #
         
        geoip = {}
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
                        while True:
                            try:
                                counter += 1
                                line = f.readline()
                                if not line:
                                    break
                                else:
                                    try:
                                        LINE = line.split(",")
                                        cidr, geoname_id, registered_country_id, represented_country_id, \
                                            is_anonymous_proxy, is_satellite_provider, *_any_other_field = LINE
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
                                            country_code = dictCountryByID[geoname_id]
                                        if country_code == "":
                                            country_code = "XX"
                                        firstIP = CIDRInfo.first_ip2int
                                        lastIP = CIDRInfo.last_ip2int
                                        geoip[firstIP] = {'cidr':cidr,'country_code':country_code,
                                                        'last_ip':lastIP }
                                    except Exception as ERR:
                                        print("Error at \""+LINE+"\" - "+str(ERR))                                    
                                    if counter % 10000 == 0:
                                        # break
                                        log(f"\r> Lines read: {counter}",end="")
                            except Exception as ERR:
                                logError("Falied at country blocks look %s"%(str(ERR)))
                                continue
                    log(f"\r- Lines read: {counter} done! {timer(elapsed())}")
                except Exception as ERR:
                    logError("Failed country cidr readline %s"%(str(ERR)))
                    return 1 
        # ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        with elapsed_timer() as elapsed:
            try:
                for cidr,v in reservedNetworks.items():
                    if cidr.find(":") < 0:
                        CIDRInfo = CIDRv4Detail(cidr)
                    else:
                        CIDRInfo = CIDRv6Detail(cidr)
                    for key,value in v.items():
                        if CIDRInfo.is_ipv6 == True and with_ipv6 == False:
                            continue
                        country_code = key
                        first_ip2int = CIDRInfo.first_ip2int
                        geoip[first_ip2int] = {'cidr':cidr,'country_code':country_code,
                                                'last_ip':CIDRInfo.last_ip2int }
                        if country_code == '14':
                            continue
                log(f"- Added {len(reservedNetworks.keys())} private/reserved networks... done! {timer(elapsed())}")
            except Exception as ERR:
                logError("%s"%(str(ERR)))
                return 1
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        geoip = dict(sorted(geoip.items(),key=lambda x:int(x[0]), reverse=False))
        if _DEBUG == True:
            with elapsed_timer() as elapsed_debug:
                with open("geoipCountry.json","w") as f:
                    json.dump(geoip,f,indent=3,sort_keys=False,ensure_ascii=False)
                logDebug(f"- Saving debug file geoipCountry.json... done! {timer(elapsed_debug())}")
        with elapsed_timer() as elapsed_debug:
            ipCounter_v4, ipCounter_v6 = 0, 0
            for key,val in geoip.items():
                if val['last_ip'] <= numIPsv4[0]:
                    ipCounter_v4 += numIPsv4[int(val['cidr'].split("/")[1])]
                else:
                    ipCounter_v6 += numIPsv6[int(val['cidr'].split("/")[1])]
            percentage_v4 = (ipCounter_v4 * 100) / numIPsv4[0]
            log(f"- Country IPv4 coverage {'%.2f%%'%(percentage_v4)}")
            if with_ipv6 == True:
                percentage_v6 = (ipCounter_v6 * 100) / numIPsv6[0]
                log(f"- Country IPv6 coverage {'%.2f%%'%(percentage_v6)}")
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        if asn_dir != "":
            with elapsed_timer() as elapsed:
                try:
                    geoipASN = dict(sorted(geoipASN.items(),key=lambda x:int(x[0]), reverse=False))
                    listFirstIPASN = [int(key) for key in geoipASN.keys()]
                    log(f"- listFirstIPASN with {len(listFirstIPASN)} items... done! {timer(elapsed())}")
                except Exception as ERR:
                    logError(f"Failed to create listFirstIPASN %s"%(str(ERR)))
                    return 1     
            with elapsed_timer() as elapsed:
                try:
                    listASNID = [int(val['asn_id']) for key,val in geoipASN.items()]
                    log(f"- listASNID with {len(listASNID)} items... done! {timer(elapsed())}")
                except Exception as ERR:
                    logError(f"Failed to create listASNID %s"%(str(ERR)))
                    return 1               
        else:
            listASNID = []
            listFirstIPASN = []
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        with elapsed_timer() as elapsed:
            try:
                dictCountryByCode = dict(sorted(dictCountryByCode.items(),key=lambda x:x[0], reverse=False))
                listLocation = [f"{key}:{val}" for key,val in dictCountryByCode.items()]
                log(f"- listLocation language {language} with {len(listLocation)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listLocation %s"%(str(ERR)))
                return 1
        with elapsed_timer() as elapsed:
            try:
                geoip = dict(sorted(geoip.items(),key=lambda x:int(x[0]), reverse=False))
                listFirstIP = [int(key) for key in geoip.keys()]
                log(f"- listFirstIP with {len(listFirstIP)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listFirstIP %s"%(str(ERR)))
                return 1
        with elapsed_timer() as elapsed:
            try:
                ListNetLength = [int(val['cidr'].split('/')[1]) for key,val in geoip.items()]
                log(f"- ListNetLength with {len(ListNetLength)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create ListNetLength %s"%(str(ERR)))
                return 1
        with elapsed_timer() as elapsed:
            try:
                listCountryCode = [int(f"{list(dictCountryByCode.keys()).index(val['country_code'])}") for key,val in geoip.items()]
                log(f"- listCountryCode with {len(listCountryCode)} items... done! {timer(elapsed())}")
            except Exception as ERR:
                logError(f"Failed to create listCountryCode %s"%(str(ERR)))
                return 1
        #────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        _SOURCE_INFO = source_info
        listAsnNames = list(asnNamesDict.keys())
        mainList = list(split_list(listFirstIP,LIST_SLICE_SIZE))
        mainListCodes = list(split_list(listCountryCode,LIST_SLICE_SIZE))
        mainListNetLength = list(split_list(ListNetLength,LIST_SLICE_SIZE))
        mainListASN = list(split_list(listFirstIPASN,LIST_SLICE_SIZE))
        mainListASNID = list(split_list(listASNID,LIST_SLICE_SIZE))
        sliceInfo = {'num_keys':len(mainList),
                    'total_networks':len(listFirstIP),
                    'slice_size':LIST_SLICE_SIZE,
                    'length_last_list':len(mainList[-1]) }
        mainIndex = []
        for item in mainList:
            mainIndex.append(item[0])
        mainIndexASN = []
        for item in mainListASN:
            mainIndexASN.append(item[0])        

        log(f"- Using an index with {len(mainIndex)} chunks for COUNTRY lookups...")
        geoipList = [mainIndex, mainList, mainListCodes, mainListNetLength, mainIndexASN, mainListASN, mainListASNID]
        stringToHash = str(mainIndex)+":"+str(len(listFirstIP))
        hashMD5 = get_md5(stringToHash)
        with elapsed_timer() as elapsed:
            database = [__DAT_VERSION__,    # integer
                        listLocation,       # list      "country_code:country_name"
                        listAsnNames,       # list      
                        geoipList,          # geoipList = [mainIndex, mainList, mainListCodes, mainListNetLength, mainIndexASN, mainListASN, mainListASNID]
                        hashMD5,            # hashmd5 = mainIndex + ":" + lenght of all records
                        str(sliceInfo),     # string (dict = 'num_keys','total_networks','slice_size''length_last_list')
                        _SOURCE_INFO]       # string 
            log(f"- Preparing database {GEOIP2FAST_DAT_FILENAME_GZ}... {timer(elapsed())}")
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        if _DEBUG == True:
            with elapsed_timer() as elapsed_debug:
                with open("database.json","w") as f:
                    json.dump(database,f,indent=3,sort_keys=False,ensure_ascii=False)            
                logDebug(f"- Saving debug file database.json... done! {timer(elapsed_debug())}")
            with elapsed_timer() as elapsed_debug:
                with open("listAsnNames.json","w") as f:
                    json.dump(listAsnNames,f,indent=3,sort_keys=False,ensure_ascii=False)                        
                logDebug(f"- Saving debug file listAsnNames.json... done! {timer(elapsed_debug())}")
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        with elapsed_timer() as elapsed_save_gzip:
            with gzip.GzipFile(filename=os.path.join(output_dir,GEOIP2FAST_DAT_FILENAME_GZ), mode='wb', compresslevel=9) as f:
                pickle.dump(database,f,pickle.HIGHEST_PROTOCOL)
            f.close()
        log(f"- Saved file {os.path.join(output_dir,GEOIP2FAST_DAT_FILENAME_GZ)} {timer(elapsed_save_gzip())}")

    log(cYellow(f">>> ALL DONE!!! {timer(elapsed_total())}"))
    
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
    fileimport = parser.add_argument_group("Import options")
    fileimport.add_argument("--country-dir",dest='country_dir',action="store",default="",metavar="<directory>",help="Provide the full path of the CSV files GeoLite2-Country-Blocks-IPv4.csv and GeoLite2-Country-Locations-XX.csv files. Only the path of directory. Mandatory.")
    fileimport.add_argument("--asn-dir",dest='asn_dir',action="store",metavar="<directory>",default="",help="Provide the full path of the CSV files GeoLite2-ASN-Blocks-IPv4.csv files. Mandatory only if you want to create the dat file with ASN support.")
    fileimport.add_argument("--output-dir",dest='output_dir',action="store",default="",metavar="<directory>",help="Define the output directory to save the file geoip2fast.dat.gz. Any file with the same name will be renamed. Mandatory.")
    fileimport.add_argument("--language",dest='language',action="store",default="en",choices=AVAILABLE_LANGUAGES,help="Choose the language of locations that you want to use. Default: en.")
    fileimport.add_argument("--with-ipv6",dest='withipv6',action="store_true",default=False,help="Include IPv6 network ranges.")
    optional = parser.add_argument_group("More options")
    optional.add_argument('-v',dest="verbose",action='store_true',default=False,help='0|Show useful messages for debugging.')
    optional.add_argument('-h','--help',action='help',help='0|Show a help message about the allowed commands.')
    optional.add_argument('--version','-version',action='version',help='0|Show the application version.',version="%s v%s"%(__appid__,__version__))
    # HIDDEN
    fileimport.add_argument("--source-info",dest='sourceinfo',action="store",metavar="<text>",default="",help=SUPPRESS)
    optional.add_argument('--debug',dest="debug",action='store_true',default=False,help=SUPPRESS)

    ##────── do the parse ───────────────────────────────────────────────────────────────────────────────────────────────────
    args = parser.parse_args()
    ##────── Se não houve subcomando, exiba o help ─────────────────────────────────────────────────────────────────────────

    if ((args.country_dir != "") + (args.output_dir != "") != 2):
        parser.print_help()
        print("")
        sys.exit(0)
    
    _DEBUG = args.debug
    
    with geoip2dat():
        sys.exit(run(args.country_dir,args.asn_dir,args.output_dir,args.language,args.withipv6,args.sourceinfo))
    
if __name__ == "__main__":
    sys.exit(main_function())
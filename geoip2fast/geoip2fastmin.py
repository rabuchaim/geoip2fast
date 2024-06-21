#!/usr/bin/env python3
# encoding: utf-8
# -*- coding: utf-8 -*-
"""
GeoIP2FastMin - Version v1.2.2

Author: Ricardo Abuchaim - ricardoabuchaim@gmail.com
        https://github.com/rabuchaim/geoip2fast/

License: MIT

.oPYo.               o  .oPYo. .oPYo.  ooooo                 o    o     o  o
8    8               8  8    8     `8  8                     8    8b   d8
8      .oPYo. .oPYo. 8 o8YooP'    oP' o8oo   .oPYo. .oPYo.  o8P   8`b d'8 o8 odYo.
8   oo 8oooo8 8    8 8  8      .oP'    8     .oooo8 Yb..     8    8 `o' 8  8 8' `8
8    8 8.     8    8 8  8      8'      8     8    8   'Yb.   8    8     8  8 8   8
`YooP8 `Yooo' `YooP' 8  8      8ooooo  8     `YooP8 `YooP'   8    8     8  8 8   8
:....8 :.....::.....:..:..:::::.......:..:::::.....::.....:::..:::..::::..:....::..
:::::8 ::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::..::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

This version has been reduced to essential functions. Just copy the entire class and paste it into your
code and use the GeoIP2Fast databases with countries, cities and asn. Is Pure Python! No dependencies.

From GeoIP2Fast's natural code, we removed the coverage testing functions, missing ips, automatic updates, 
and a few other things. Nothing that affects speed. Usage examples:

    G = GeoIP2FastMin(verbose=False,geoip2fast_data_file="")

    print(G.startup_line_text)
    print(G.database_path)

    result = G.lookup("1.1.1.1")
    
    print(result.country_code)
    print(result.country_name)
    print(result.cidr)
    print(result.pp_json())
    G.self_test(max_ips=30)

"""

class GeoIP2FastMin(object):
    import os, sys, bisect, pickle, ctypes, subprocess, gzip, json, random, socket, struct, binascii, time
    __appid__   = "GeoIP2Fast"
    __version__ = "1.2.2"
    GEOIP2FAST_DAT_GZ_FILE = os.path.join(os.path.dirname(__file__),"geoip2fast.dat.gz")    
    os.environ["PYTHONWARNINGS"]    = "ignore"
    os.environ["PYTHONIOENCODING"]  = "utf-8"        
    ##──── Define here what do you want to return if one of these errors occurs ─────────────────────────────────────────────────────
    ##──── ECCODE = Error Country Code ───────────────────────────────────────────────────────────────────────────────────────────────
    GEOIP_ECCODE_PRIVATE_NETWORKS, GEOIP_ECCODE_NETWORK_NOT_FOUND   = "--", "--"
    GEOIP_ECCODE_INVALID_IP, GEOIP_ECCODE_LOOKUP_INTERNAL_ERROR     = "", ""
    GEOIP_NOT_FOUND_STRING              = "<not found in database>"
    GEOIP_INTERNAL_ERROR_STRING         = "<internal lookup error>"
    GEOIP_INVALID_IP_STRING             = "<invalid ip address>"
    ##──── Number os possible IPs in a network range. (/0, /1 .. /8 .. /24 .. /30, /31, /32) ─────────────────────────────────────────
    numIPsv4 = sorted([2**num for num in range(0,33)],reverse=True) # from 0 to 32
    numIPsv6 = sorted([2**num for num in range(0,129)],reverse=True) # from 0 to 128
    MAX_IPv4 = numIPsv4[0]
    ##──── CLASS INIT ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def __init__(self, verbose=False, geoip2fast_data_file=""):
        self.name = "GeoIP2FastMin"
        self.ipv6, self.city, self.asn, self.is_loaded = False, False, False, False
        self.data_file, self._load_data_text = "", ''
        self.verbose = verbose
        if verbose == False:
            self._print_verbose = self.__print_verbose_empty
        ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────        
        self.error_code_private_networks        = self.GEOIP_ECCODE_PRIVATE_NETWORKS
        self.error_code_network_not_found       = self.GEOIP_ECCODE_NETWORK_NOT_FOUND
        self.error_code_invalid_ip              = self.GEOIP_ECCODE_INVALID_IP
        self.error_code_lookup_internal_error   = self.GEOIP_ECCODE_LOOKUP_INTERNAL_ERROR
        ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────        
        if geoip2fast_data_file != "":
            try:
                if self.os.path.isfile(geoip2fast_data_file) == True:
                    self.data_file = geoip2fast_data_file
                else:
                    if geoip2fast_data_file.find("/") < 0:
                        databasePath = self.__locate_database_file(geoip2fast_data_file)
                        if databasePath is False:
                            raise self.GeoIPError("Unable to find GeoIP2Fast database file %s"%(self.os.path.basename(geoip2fast_data_file)))
                        else:
                            self.data_file = databasePath
                    else:
                        raise self.GeoIPError("Check path of specified file and try again.")
            except Exception as ERR:
                raise self.GeoIPError("Unable to access the specified file %s. %s"%(geoip2fast_data_file,str(ERR)))
            
        self.__load_data(self.data_file, verbose)
    ##──── GeoIP2Fast Exception Class ────────────────────────────────────────────────────────────────────────────────────────────────    
    class GeoIPError(Exception):
        def __init__(self, message):
            self.message = message
        def __str__(self):
            return self.message
        def __repr__(self):
            return self.message        
    class CityDetail(object):
        def __init__(self, city_string="||||"):
            try:
                self.name, self.subdivision_code, self.subdivision_name, self.subdivision2_code, self.subdivision2_name = city_string.split("|")
            except:
                self.name, self.subdivision_code, self.subdivision_name, self.subdivision2_code, self.subdivision2_name = GeoIP2FastMin.GEOIP_INTERNAL_ERROR_STRING,"","","",""
        def to_dict(self):
            return {
                "name": self.name,
                "subdivision_code": self.subdivision_code,
                "subdivision_name": self.subdivision_name}
    ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────            
    class GeoIPDetail(object):
        def __init__(self, ip, country_code="", country_name="", cidr="", is_private=False, asn_name="", asn_cidr="", elapsed_time=""):
            self.ip, self.country_code, self.country_name, self.cidr, self.hostname = ip, country_code, country_name, cidr, ""
            self.is_private, self.asn_name, self.asn_cidr, self.elapsed_time = is_private, asn_name, asn_cidr, elapsed_time
        @property
        def city(self):
            return GeoIP2FastMin.CityDetail()
        def __str__(self):
            return f"{self.__dict__}"
        def __repr__(self):
            return f"{self.to_dict()}"    
        def get_hostname(self,dns_timeout=0.1):
            try:
                startTime = GeoIP2FastMin.time.perf_counter()
                self.socket.setdefaulttimeout(dns_timeout)
                result = self.socket.gethostbyaddr(self.ip)[0]
                self.hostname = result if result != self.ip else ""
                self.elapsed_time_hostname = "%.9f sec"%(GeoIP2FastMin.time.perf_counter()-startTime)
                return self.hostname
            except OSError as ERR:
                self.hostname = f"<{str(ERR.strerror)}>"
                return self.hostname
            except Exception as ERR:
                self.hostname = "<dns resolver error>"
                return self.hostname        
        def to_dict(self):
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
                if not hasattr(self, 'city'):
                    del d['city']
                try:
                    a = self.elapsed_time_hostname
                    d['elapsed_time_hostname'] = self.elapsed_time_hostname
                except:
                    pass
                return d
            except Exception as ERR:
                raise GeoIP2FastMin.GeoIPError("Failed to_dict() %s"%(str(ERR)))
        def pp_json(self,indent=3,sort_keys=False,print_result=False):
            try:
                dump = GeoIP2FastMin.json.dumps(self.to_dict(),sort_keys=sort_keys,indent=indent,ensure_ascii=False)
                if print_result == True:
                    print(dump)
                return dump
            except Exception as ERR:
                raise GeoIP2FastMin.GeoIPError("Failed pp_json() %s"%(str(ERR)))
    class GeoIPDetailCity(GeoIPDetail):
        """Extended version of GeoIPDetail with city information
        """
        def __init__(self, ip, country_code="", country_name="", city=None, cidr="", is_private=False, asn_name="", asn_cidr="", elapsed_time=""):
            super().__init__(ip, country_code, country_name, cidr, is_private, asn_name, asn_cidr, elapsed_time)
            self._city = city if city else GeoIP2FastMin.CityDetail()
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
            curDir = self.os.path.join(self.os.path.abspath(self.os.path.curdir),filename) # path of your application
            libDir = self.os.path.join(self.os.path.dirname(__file__),filename)       # path where the library is installed
        except Exception as ERR:
            raise GeoIP2FastMin.GeoIPError("Unable to determine the path of application %s. %s"%(filename,str(ERR)))
        try:
            self.os.stat(curDir).st_mode
            return curDir
        except Exception as ERR:            
            try:
                self.os.stat(libDir).st_mode 
                return libDir
            except Exception as ERR:
                raise GeoIP2FastMin.GeoIPError("Unable to determine the path of library %s - %s"%(filename,str(ERR)))
    ##──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    def __load_data(self, gzip_data_file:str, verbose=False)->bool:        
        global __DAT_VERSION__, source_info, totalNetworks,mainListNamesCountry,geoipCountryNamesDict,geoipCountryCodesList,\
               mainIndex,mainListNamesCountry,mainListFirstIP,mainListIDCountryCodes,mainListNetlength,\
               mainIndexASN,mainListNamesASN,mainListFirstIPASN,mainListIDASN,mainListNetlengthASN,\
               mainListNamesCity, mainListIDCity
        if self.is_loaded == True:
            return True   
        self._print_verbose = self.__print_verbose_regular if verbose == True else self.__print_verbose_empty
        startMem = self.get_mem_usage()
        startLoadData = self.time.perf_counter()
        ##──── Try to locate the database file in the directory of the application that called GeoIP2Fast() ─────────────────────────
        ##──── or in the directory of the GeoIP2Fast Library ────────────────────────────────────────────────────────────────────────
        try:
            if gzip_data_file == "":
                gzip_data_file = GeoIP2FastMin.GEOIP2FAST_DAT_GZ_FILE
                try:
                    databasePath = self.__locate_database_file(self.os.path.basename(gzip_data_file))
                    if databasePath is False:
                        raise GeoIP2FastMin.GeoIPError("(1) Unable to find GeoIP2Fast database file %s"%(self.os.path.basename(gzip_data_file)))
                    else:
                        self.data_file = databasePath
                except Exception as ERR:
                    raise GeoIP2FastMin.GeoIPError("(2) Unable to find GeoIP2Fast database file %s %s"%(self.os.path.basename(gzip_data_file),str(ERR)))
        except Exception as ERR:
            raise GeoIP2FastMin.GeoIPError("Failed at locate data file %s"%(str(ERR)))        
        ##──── Open the dat.gz file ──────────────────────────────────────────────────────────────────────────────────────────────────────
        try:
            try:
                inputFile = self.gzip.open(str(self.data_file),'rb')
            except:
                try:
                    inputFile = open(str(self.data_file).replace(".gz",""),'rb')
                    self.data_file = self.data_file.replace(".gz","")
                except Exception as ERR:
                    raise GeoIP2FastMin.GeoIPError(f"Unable to find {gzip_data_file} or {gzip_data_file} {str(ERR)}")
        except Exception as ERR:
            raise GeoIP2FastMin.GeoIPError(f"Failed to 'load' GeoIP2Fast! the data file {gzip_data_file} appears to be invalid or does not exist! {str(ERR)}")
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────        
        self._database_path = self.os.path.realpath(self.data_file)
        ##──── Load the dat.gz file into memory ──────────────────────────────────────────────────────────────────────────────────────────
        try:
            __DAT_VERSION__, source_info, totalNetworks, mainDatabase = self.pickle.load(inputFile)
            if __DAT_VERSION__ != 120:
                raise GeoIP2FastMin.GeoIPError(f"Failed to pickle the data file {gzip_data_file}. Reason: Invalid version - requires 120, current {str(__DAT_VERSION__)}")
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
                mainIndex,mainListNamesCountry,mainListNamesCity,mainListFirstIP,mainListIDCity,mainListNetlength = mainDatabase
            ##──── CITY WITH ASN ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
            elif self.city == True and self.asn == True:
                mainIndex,mainIndexASN,mainListNamesCountry,mainListNamesCity,mainListNamesASN,\
                mainListFirstIP,mainListFirstIPASN,mainListIDCity,mainListIDASN,mainListNetlength,mainListNetlengthASN = mainDatabase
            self.ipv6 = mainIndex[-1] > GeoIP2FastMin.numIPsv4[0]
            geoipCountryNamesDict = {item.split(":")[0]:item.split(":")[1] for item in mainListNamesCountry}
            geoipCountryCodesList = list(geoipCountryNamesDict.keys())
            inputFile.close()
            del inputFile
        except Exception as ERR:
            raise GeoIP2FastMin.GeoIPError(f"Failed to pickle the data file {gzip_data_file} {str(ERR)}")
        ##──── Warming-up ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        try:
            [self._main_index_lookup(iplong) for iplong in [2894967295]]
        except Exception as ERR:
            raise GeoIP2FastMin.GeoIPError("Failed at warming-up... exiting... %s"%(str(ERR)))
        ##──── Load Time Info ──────────────────────────────────────────────────────────────────────────────────────────────────────────
        try:
            totalLoadTime = (self.time.perf_counter() - startLoadData)
            totalMemUsage = abs((self.get_mem_usage() - startMem))
            self._load_data_text = f"GeoIP2Fast v{self.__version__} is ready! {self.os.path.basename(gzip_data_file)} "+ \
                "loaded with %s networks in %.5f seconds and using %.2f MiB."%('{:,d}'.format(totalNetworks).replace(',','.'),totalLoadTime,totalMemUsage)
            self._print_verbose(self._load_data_text)
        except Exception as ERR:
            raise GeoIP2FastMin.GeoIPError("Failed at the end of load data %s"%(str(ERR)))
        ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        self.is_loaded = True
        return True
    @property
    def startup_line_text(self):
        return self._load_data_text
    def _main_index_lookup(self,iplong):
        try:
            matchRoot = self.bisect.bisect_right(mainIndex,iplong)-1
            matchChunk = self.bisect.bisect_right(mainListFirstIP[matchRoot],iplong)-1
            first_ip2int = mainListFirstIP[matchRoot][matchChunk]
            netlen = mainListNetlength[matchRoot][matchChunk]
            if iplong <= GeoIP2FastMin.MAX_IPv4:
                last_ip2int = first_ip2int + GeoIP2FastMin.numIPsv4[netlen]-1
            else:
                last_ip2int = first_ip2int + GeoIP2FastMin.numIPsv6[netlen]-1
            return matchRoot, matchChunk, first_ip2int, last_ip2int, netlen
        except Exception as ERR:
            return GeoIP2FastMin.GeoIPError("Failed at _main_index_lookup: %s"%(str(ERR)))
    def _country_lookup(self,match_root,match_chunk):
        try:
            country_code_index = mainListIDCountryCodes[match_root][match_chunk]
            country_code, country_name = mainListNamesCountry[country_code_index].split(":")
            is_private = country_code_index < 16
            country_code = self.error_code_private_networks if is_private else country_code
            return country_code, country_name, is_private
        except Exception as ERR:
            return GeoIP2FastMin.GeoIPError("Failed at _country_lookup: %s"%(str(ERR)))
    def _city_country_name_lookup(self,country_code):
        try:
            country_name = geoipCountryNamesDict[country_code]        
            country_code_index = geoipCountryCodesList.index(country_code)
            is_private = country_code_index < 16
            country_code = self.error_code_private_networks if is_private else country_code
            return country_code, country_name, is_private
        except Exception as ERR:
            return GeoIP2FastMin.GeoIPError("Failed at _city_country_name_lookup: %s"%(str(ERR)))
    def _city_lookup(self,match_root,match_chunk):
        try:
            code = mainListIDCity[match_root][match_chunk]
            country_code, city_name = mainListNamesCity[code].split(":")
            country_code, country_name, is_private = self._city_country_name_lookup(country_code)            
            city_info = GeoIP2FastMin.CityDetail(city_name)
            return country_code, country_name, city_info, is_private
        except Exception as ERR:
            return GeoIP2FastMin.GeoIPError("Failed at _country_lookup: %s"%(str(ERR)))
    def _asn_lookup(self,iplong):
        if self.asn == False:
            return "", ""
        try:
            matchRoot = self.bisect.bisect_right(mainIndexASN,iplong)-1
            matchChunk = self.bisect.bisect_right(mainListFirstIPASN[matchRoot],iplong)-1
            first_ip2int = mainListFirstIPASN[matchRoot][matchChunk]
            asn_id = mainListIDASN[matchRoot][matchChunk]
            netlen = mainListNetlengthASN[matchRoot][matchChunk]
            if not self.ipv6:
                if iplong > ((first_ip2int + GeoIP2FastMin.numIPsv4[netlen]) - 1):
                    return "", ""
            else:
                if iplong > ((first_ip2int + GeoIP2FastMin.numIPsv6[netlen]) - 1):
                    return "", ""
            return mainListNamesASN[asn_id], self._int2ip(first_ip2int)+"/"+str(netlen)
        except Exception as ERR:
            return "", ""
    def _ip2int(self,ipaddr:str)->int:
        try:
            try:
                return int(self.struct.unpack('>L', self.socket.inet_aton(ipaddr))[0])
            except:
                return int.from_bytes(self.socket.inet_pton(self.socket.AF_INET6, ipaddr), byteorder='big')
        except Exception as ERR:
            raise GeoIP2FastMin.GeoIPError("Failed at ip2int: %s"%(str(ERR)))
    def _int2ip(self,iplong:int)->str:
        try:
            if iplong < GeoIP2FastMin.MAX_IPv4:
                return self.socket.inet_ntoa(self.struct.pack('>L', iplong))
            else:
                return self.socket.inet_ntop(self.socket.AF_INET6, self.binascii.unhexlify(hex(iplong)[2:].zfill(32)))
        except Exception as ERR:
            raise GeoIP2FastMin.GeoIPError("Failed at int2ip: %s"%(str(ERR)))
    def set_error_code_private_networks(self,new_value)->str:
        global GEOIP_ECCODE_PRIVATE_NETWORKS
        try:
            self.error_code_private_networks = new_value
            GEOIP_ECCODE_PRIVATE_NETWORKS = new_value
            return new_value
        except Exception as ERR:
            raise GeoIP2FastMin.GeoIPError("Unable to set a new value for GEOIP_ECCODE_PRIVATE_NETWORKS: %s"%(str(ERR)))
    def set_error_code_network_not_found(self,new_value)->str:
        global GEOIP_ECCODE_NETWORK_NOT_FOUND
        try:
            self.error_code_network_not_found = new_value
            GEOIP_ECCODE_NETWORK_NOT_FOUND = new_value
            return new_value
        except Exception as ERR:
            raise GeoIP2FastMin.GeoIPError("Unable to set a new value for GEOIP_ECCODE_NETWORK_NOT_FOUND: %s"%(str(ERR)))
    ##──── NO-CACHE: This function cannot be cached to don´t cache the elapsed timer. ────────────────────────────────────────────────────────────
    def lookup(self,ipaddr:str)->GeoIPDetail:
        startTime = self.time.perf_counter()
        try:
            iplong = self._ip2int(ipaddr)
        except Exception as ERR:
            return GeoIP2FastMin.GeoIPDetail(ipaddr,country_code=self.error_code_invalid_ip,\
                    country_name=GeoIP2FastMin.GEOIP_INVALID_IP_STRING,elapsed_time='%.9f sec'%(self.time.perf_counter()-startTime))
        try:
            matchRoot, matchChunk, first_ip2int, last_ip2int, netlen = self._main_index_lookup(iplong)
            if iplong > last_ip2int:
                return GeoIP2FastMin.GeoIPDetail(ip=ipaddr,country_code=self.error_code_network_not_found, \
                            country_name=GeoIP2FastMin.GEOIP_NOT_FOUND_STRING,elapsed_time='%.9f sec'%(self.time.perf_counter()-startTime))            
            cidr = self._int2ip(first_ip2int)+"/"+str(netlen)
            asn_name, asn_cidr = self._asn_lookup(iplong)
            if self.country:
                country_code, country_name, is_private = self._country_lookup(matchRoot, matchChunk)
                ##──── SUCCESS! ────
                return GeoIP2FastMin.GeoIPDetail(ipaddr,country_code,country_name,cidr,is_private,asn_name,asn_cidr,elapsed_time='%.9f sec'%((self.time.perf_counter()-startTime)))
            else:
                country_code, country_name, city_info, is_private = self._city_lookup(matchRoot, matchChunk)
                ##──── SUCCESS! ────
                try:
                    return GeoIP2FastMin.GeoIPDetailCity(ipaddr,country_code,country_name,city_info,cidr,is_private,asn_name,asn_cidr,elapsed_time='%.9f sec'%((self.time.perf_counter()-startTime)))
                except Exception as ERR:
                    raise Exception(ERR)
            ##────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
        except Exception as ERR:
            return GeoIP2FastMin.GeoIPDetail(ip=ipaddr,country_code=self.error_code_lookup_internal_error,\
                    country_name=GeoIP2FastMin.GEOIP_INTERNAL_ERROR_STRING,elapsed_time='%.9f sec'%(self.time.perf_counter()-startTime))
    #──── GET MEMORY USAGE ───────────────────────────────────────────────────────────────────────────────────────────────────────
    def get_mem_usage(self)->float:
        ''' Memory usage in MiB '''
        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        class PROCESS_MEMORY_COUNTERS(self.ctypes.Structure):
            _fields_ = [("cb", self.ctypes.c_ulong),
                        ("PageFaultCount", self.ctypes.c_ulong),
                        ("PeakWorkingSetSize", self.ctypes.c_size_t),
                        ("WorkingSetSize", self.ctypes.c_size_t),
                        ("QuotaPeakPagedPoolUsage", self.ctypes.c_size_t),
                        ("QuotaPagedPoolUsage", self.ctypes.c_size_t),
                        ("QuotaPeakNonPagedPoolUsage", self.ctypes.c_size_t),
                        ("QuotaNonPagedPoolUsage", self.ctypes.c_size_t),
                        ("PagefileUsage", self.ctypes.c_size_t),
                        ("PeakPagefileUsage", self.ctypes.c_size_t)]
        try: 
            result = self.subprocess.check_output(['ps', '-p', str(self.os.getpid()), '-o', 'rss='])
            return float(int(result.strip()) / 1024)
        except:
            try:
                pid = self.ctypes.windll.kernel32.GetCurrentProcessId()
                process_handle = self.ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
                counters = PROCESS_MEMORY_COUNTERS()
                counters.cb = self.ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
                if self.ctypes.windll.psapi.GetProcessMemoryInfo(process_handle, self.ctypes.byref(counters), self.ctypes.sizeof(counters)):
                    memory_usage = counters.WorkingSetSize
                    return float((int(memory_usage) / 1024) / 1024)
            except:
                return 0.0
    def self_test(self,max_ips=30):
        """
            Do a self-test with some random IPs
        """              
        ip_list = []
        ip_list.append("x"+self._int2ip(self.random.randint(16777216,3758096383)).replace(".",",")) # generates an invalid IP inserting the 'x' letter and changing dot by comma
        ip_list.append(self._int2ip(self.random.randint(16777216,3758096383))+"/32") # generates an invalid IP adding '/32' to the end. Is a valid CIDR but an invalid IP
        ip_list.append(self._int2ip(self.random.randint(397189376,397191423))) # generates a random IP between 23.172.161.0 and 23.172.168.255 to force a 'not found' response
        ip_list.append(self._int2ip(self.random.choice([self.random.randint(167772160,184549375),self.random.randint(3232235520,3232301055),self.random.randint(2886729728,2887778303)]))) # generates a random IP of a private network
        while len(ip_list) < max_ips:
                ip_list.append(self._int2ip(self.random.randint(16777216,3758096383)))
        print("\nStarting a self-test with %s randomic IPv4 addresses...\n"%('{:,d}'.format(len(ip_list))))
        avgList, avgCacheList = [], []
        for IP in ip_list:
            geoip = self.lookup(IP)
            avgList.append(float(geoip.elapsed_time.split(" ")[0]))
            cachedResult = self.lookup(IP)
            avgCacheList.append(float(cachedResult.elapsed_time.split(" ")[0]))
            print("> "+IP.ljust(18)+" "+str(geoip.country_code).ljust(3)+str(geoip.country_name[:30]).ljust(30)+ \
                " ["+geoip.elapsed_time+"]  Cached > ["+cachedResult.elapsed_time+"] "+geoip.asn_name)
        print("\n\t- Average Lookup Time: %.9f seconds - Average Cached Lookups: %.9f seconds.\n"%(sum(sorted(avgList)[1:-1])/(len(ip_list)-2),sum(sorted(avgCacheList)[1:-1])/(len(ip_list)-2)))

if __name__ == "__main__":
    G = GeoIP2FastMin(verbose=True,geoip2fast_data_file="")
    G.self_test()
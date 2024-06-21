#!/usr/bin/env python3
# encoding: utf-8
# -*- coding: utf-8 -*-
"""
GeoIP2FastMin - Version v1.2.2

Author: Ricardo Abuchaim - ricardoabuchaim@gmail.com
        https://github.com/rabuchaim/geoip2fast/

License: MIT

.oPYo.               o  .oPYo. .oPYo.  ooooo                 o    o     o  o        o  d'b  o             8
8    8               8  8    8     `8  8                     8    8b   d8              8                  8
8      .oPYo. .oPYo. 8 o8YooP'    oP' o8oo   .oPYo. .oPYo.  o8P   8`b d'8 o8 odYo. o8 o8P  o8 .oPYo. .oPYo8
8   oo 8oooo8 8    8 8  8      .oP'    8     .oooo8 Yb..     8    8 `o' 8  8 8' `8  8  8    8 8oooo8 8    8
8    8 8.     8    8 8  8      8'      8     8    8   'Yb.   8    8     8  8 8   8  8  8    8 8.     8    8
`YooP8 `Yooo' `YooP' 8  8      8ooooo  8     `YooP8 `YooP'   8    8     8  8 8   8  8  8    8 `Yooo' `YooP'
:....8 :.....::.....:..:..:::::.......:..:::::.....::.....:::..:::..::::..:....::..:..:..:::..:.....::.....:
:::::8 :::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
:::::..:::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

This version was minified by pyminify. Just copy the entire class and paste it into your code and use the 
GeoIP2Fast databases with countries, cities and asn. Is Pure Python! No dependencies.

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
class GeoIP2FastMin:
	import os,sys,bisect,pickle,ctypes,subprocess,gzip,json,random,socket,struct,binascii,time;__appid__='GeoIP2Fast';__version__='1.2.2';GEOIP2FAST_DAT_GZ_FILE=os.path.join(os.path.dirname(__file__),'geoip2fast.dat.gz');os.environ['PYTHONWARNINGS']='ignore';os.environ['PYTHONIOENCODING']='utf-8';GEOIP_ECCODE_PRIVATE_NETWORKS,GEOIP_ECCODE_NETWORK_NOT_FOUND='--','--';GEOIP_ECCODE_INVALID_IP,GEOIP_ECCODE_LOOKUP_INTERNAL_ERROR='','';GEOIP_NOT_FOUND_STRING='<not found in database>';GEOIP_INTERNAL_ERROR_STRING='<internal lookup error>';GEOIP_INVALID_IP_STRING='<invalid ip address>';numIPsv4=sorted([2**A for A in range(0,33)],reverse=True);numIPsv6=sorted([2**A for A in range(0,129)],reverse=True);MAX_IPv4=numIPsv4[0]
	def __init__(A,verbose=False,geoip2fast_data_file=''):
		C=verbose;B=geoip2fast_data_file;A.name='GeoIP2FastMin';A.ipv6,A.city,A.asn,A.is_loaded=False,False,False,False;A.data_file,A._load_data_text='','';A.verbose=C
		if C==False:A._print_verbose=A.__print_verbose_empty
		A.error_code_private_networks=A.GEOIP_ECCODE_PRIVATE_NETWORKS;A.error_code_network_not_found=A.GEOIP_ECCODE_NETWORK_NOT_FOUND;A.error_code_invalid_ip=A.GEOIP_ECCODE_INVALID_IP;A.error_code_lookup_internal_error=A.GEOIP_ECCODE_LOOKUP_INTERNAL_ERROR
		if B!='':
			try:
				if A.os.path.isfile(B)==True:A.data_file=B
				elif B.find('/')<0:
					D=A.__locate_database_file(B)
					if D is False:raise A.GeoIPError('Unable to find GeoIP2Fast database file %s'%A.os.path.basename(B))
					else:A.data_file=D
				else:raise A.GeoIPError('Check path of specified file and try again.')
			except Exception as E:raise A.GeoIPError('Unable to access the specified file %s. %s'%(B,str(E)))
		A.__load_data(A.data_file,C)
	class GeoIPError(Exception):
		def __init__(A,message):A.message=message
		def __str__(A):return A.message
		def __repr__(A):return A.message
	class CityDetail:
		def __init__(A,city_string='||||'):
			try:A.name,A.subdivision_code,A.subdivision_name,A.subdivision2_code,A.subdivision2_name=city_string.split('|')
			except:A.name,A.subdivision_code,A.subdivision_name,A.subdivision2_code,A.subdivision2_name=GeoIP2FastMin.GEOIP_INTERNAL_ERROR_STRING,'','','',''
		def to_dict(A):return{'name':A.name,'subdivision_code':A.subdivision_code,'subdivision_name':A.subdivision_name}
	class GeoIPDetail:
		def __init__(A,ip,country_code='',country_name='',cidr='',is_private=False,asn_name='',asn_cidr='',elapsed_time=''):A.ip,A.country_code,A.country_name,A.cidr,A.hostname=ip,country_code,country_name,cidr,'';A.is_private,A.asn_name,A.asn_cidr,A.elapsed_time=is_private,asn_name,asn_cidr,elapsed_time
		@property
		def city(self):return GeoIP2FastMin.CityDetail()
		def __str__(A):return f"{A.__dict__}"
		def __repr__(A):return f"{A.to_dict()}"
		def get_hostname(A,dns_timeout=.1):
			try:D=GeoIP2FastMin.time.perf_counter();A.socket.setdefaulttimeout(dns_timeout);B=A.socket.gethostbyaddr(A.ip)[0];A.hostname=B if B!=A.ip else'';A.elapsed_time_hostname='%.9f sec'%(GeoIP2FastMin.time.perf_counter()-D);return A.hostname
			except OSError as C:A.hostname=f"<{str(C.strerror)}>";return A.hostname
			except Exception as C:A.hostname='<dns resolver error>';return A.hostname
		def to_dict(A):
			try:
				B={'ip':A.ip,'country_code':A.country_code,'country_name':A.country_name,'city':'','cidr':A.cidr,'hostname':A.hostname,'asn_name':A.asn_name,'asn_cidr':A.asn_cidr,'is_private':A.is_private,'elapsed_time':A.elapsed_time}
				if not hasattr(A,'city'):del B['city']
				try:D=A.elapsed_time_hostname;B['elapsed_time_hostname']=A.elapsed_time_hostname
				except:pass
				return B
			except Exception as C:raise GeoIP2FastMin.GeoIPError('Failed to_dict() %s'%str(C))
		def pp_json(B,indent=3,sort_keys=False,print_result=False):
			try:
				A=GeoIP2FastMin.json.dumps(B.to_dict(),sort_keys=sort_keys,indent=indent,ensure_ascii=False)
				if print_result==True:print(A)
				return A
			except Exception as C:raise GeoIP2FastMin.GeoIPError('Failed pp_json() %s'%str(C))
	class GeoIPDetailCity(GeoIPDetail):
		'Extended version of GeoIPDetail with city information\n        '
		def __init__(A,ip,country_code='',country_name='',city=None,cidr='',is_private=False,asn_name='',asn_cidr='',elapsed_time=''):super().__init__(ip,country_code,country_name,cidr,is_private,asn_name,asn_cidr,elapsed_time);A._city=city if city else GeoIP2FastMin.CityDetail()
		@property
		def city(self):return self._city
		@city.setter
		def city(self,value):raise AttributeError("Cannot set 'city' attribute in GeoIPDetailCity")
		def to_dict(B):A=super().to_dict();A['city']=B.city.to_dict();return A
	def __print_verbose_empty(A,msg):0
	def __print_verbose_regular(A,msg):print(msg,flush=True)
	def _print_debug(A,msg):print('[DEBUG] '+msg,flush=True)
	def _print_verbose(A,msg):print(msg,flush=True)
	def __locate_database_file(A,filename):
		B=filename
		try:D=A.os.path.join(A.os.path.abspath(A.os.path.curdir),B);E=A.os.path.join(A.os.path.dirname(__file__),B)
		except Exception as C:raise GeoIP2FastMin.GeoIPError('Unable to determine the path of application %s. %s'%(B,str(C)))
		try:A.os.stat(D).st_mode;return D
		except Exception as C:
			try:A.os.stat(E).st_mode;return E
			except Exception as C:raise GeoIP2FastMin.GeoIPError('Unable to determine the path of library %s - %s'%(B,str(C)))
	def __load_data(A,gzip_data_file,verbose=False):
		C=gzip_data_file;global __DAT_VERSION__,source_info,totalNetworks,mainListNamesCountry,geoipCountryNamesDict,geoipCountryCodesList,mainIndex,mainListNamesCountry,mainListFirstIP,mainListIDCountryCodes,mainListNetlength,mainIndexASN,mainListNamesASN,mainListFirstIPASN,mainListIDASN,mainListNetlengthASN,mainListNamesCity,mainListIDCity
		if A.is_loaded==True:return True
		A._print_verbose=A.__print_verbose_regular if verbose==True else A.__print_verbose_empty;G=A.get_mem_usage();H=A.time.perf_counter()
		try:
			if C=='':
				C=GeoIP2FastMin.GEOIP2FAST_DAT_GZ_FILE
				try:
					F=A.__locate_database_file(A.os.path.basename(C))
					if F is False:raise GeoIP2FastMin.GeoIPError('(1) Unable to find GeoIP2Fast database file %s'%A.os.path.basename(C))
					else:A.data_file=F
				except Exception as B:raise GeoIP2FastMin.GeoIPError('(2) Unable to find GeoIP2Fast database file %s %s'%(A.os.path.basename(C),str(B)))
		except Exception as B:raise GeoIP2FastMin.GeoIPError('Failed at locate data file %s'%str(B))
		try:
			try:D=A.gzip.open(str(A.data_file),'rb')
			except:
				try:D=open(str(A.data_file).replace('.gz',''),'rb');A.data_file=A.data_file.replace('.gz','')
				except Exception as B:raise GeoIP2FastMin.GeoIPError(f"Unable to find {C} or {C} {str(B)}")
		except Exception as B:raise GeoIP2FastMin.GeoIPError(f"Failed to 'load' GeoIP2Fast! the data file {C} appears to be invalid or does not exist! {str(B)}")
		A.database_path=A.os.path.realpath(A.data_file)
		try:
			__DAT_VERSION__,source_info,totalNetworks,E=A.pickle.load(D)
			if __DAT_VERSION__!=120:raise GeoIP2FastMin.GeoIPError(f"Failed to pickle the data file {C}. Reason: Invalid version - requires 120, current {str(__DAT_VERSION__)}")
			A.source_info=source_info['info'];A.country=source_info['country'];A.city=source_info['city'];A.asn=source_info['asn']
			if A.country==True and A.asn==False:mainIndex,mainListNamesCountry,mainListFirstIP,mainListIDCountryCodes,mainListNetlength=E
			elif A.country==True and A.asn==True:mainIndex,mainIndexASN,mainListNamesCountry,mainListNamesASN,mainListFirstIP,mainListFirstIPASN,mainListIDCountryCodes,mainListIDASN,mainListNetlength,mainListNetlengthASN=E
			elif A.city==True and A.asn==False:mainIndex,mainListNamesCountry,mainListNamesCity,mainListFirstIP,mainListIDCity,mainListNetlength=E
			elif A.city==True and A.asn==True:mainIndex,mainIndexASN,mainListNamesCountry,mainListNamesCity,mainListNamesASN,mainListFirstIP,mainListFirstIPASN,mainListIDCity,mainListIDASN,mainListNetlength,mainListNetlengthASN=E
			A.ipv6=mainIndex[-1]>GeoIP2FastMin.numIPsv4[0];geoipCountryNamesDict={A.split(':')[0]:A.split(':')[1]for A in mainListNamesCountry};geoipCountryCodesList=list(geoipCountryNamesDict.keys());D.close();del D
		except Exception as B:raise GeoIP2FastMin.GeoIPError(f"Failed to pickle the data file {C} {str(B)}")
		try:[A._main_index_lookup(B)for B in[2894967295]]
		except Exception as B:raise GeoIP2FastMin.GeoIPError('Failed at warming-up... exiting... %s'%str(B))
		try:I=A.time.perf_counter()-H;J=abs(A.get_mem_usage()-G);A._load_data_text=f"GeoIP2Fast v{A.__version__} is ready! {A.os.path.basename(C)} "+'loaded with %s networks in %.5f seconds and using %.2f MiB.'%('{:,d}'.format(totalNetworks).replace(',','.'),I,J);A._print_verbose(A._load_data_text)
		except Exception as B:raise GeoIP2FastMin.GeoIPError('Failed at the end of load data %s'%str(B))
		A.is_loaded=True;return True
	@property
	def startup_line_text(self):return self._load_data_text
	def _main_index_lookup(F,iplong):
		B=iplong
		try:
			A=F.bisect.bisect_right(mainIndex,B)-1;C=F.bisect.bisect_right(mainListFirstIP[A],B)-1;D=mainListFirstIP[A][C];E=mainListNetlength[A][C]
			if B<=GeoIP2FastMin.MAX_IPv4:G=D+GeoIP2FastMin.numIPsv4[E]-1
			else:G=D+GeoIP2FastMin.numIPsv6[E]-1
			return A,C,D,G,E
		except Exception as H:return GeoIP2FastMin.GeoIPError('Failed at _main_index_lookup: %s'%str(H))
	def _country_lookup(D,match_root,match_chunk):
		try:B=mainListIDCountryCodes[match_root][match_chunk];A,E=mainListNamesCountry[B].split(':');C=B<16;A=D.error_code_private_networks if C else A;return A,E,C
		except Exception as F:return GeoIP2FastMin.GeoIPError('Failed at _country_lookup: %s'%str(F))
	def _city_country_name_lookup(C,country_code):
		A=country_code
		try:D=geoipCountryNamesDict[A];E=geoipCountryCodesList.index(A);B=E<16;A=C.error_code_private_networks if B else A;return A,D,B
		except Exception as F:return GeoIP2FastMin.GeoIPError('Failed at _city_country_name_lookup: %s'%str(F))
	def _city_lookup(B,match_root,match_chunk):
		try:C=mainListIDCity[match_root][match_chunk];A,D=mainListNamesCity[C].split(':');A,E,F=B._city_country_name_lookup(A);G=GeoIP2FastMin.CityDetail(D);return A,E,G,F
		except Exception as H:return GeoIP2FastMin.GeoIPError('Failed at _country_lookup: %s'%str(H))
	def _asn_lookup(A,iplong):
		B=iplong
		if A.asn==False:return'',''
		try:
			C=A.bisect.bisect_right(mainIndexASN,B)-1;D=A.bisect.bisect_right(mainListFirstIPASN[C],B)-1;E=mainListFirstIPASN[C][D];G=mainListIDASN[C][D];F=mainListNetlengthASN[C][D]
			if not A.ipv6:
				if B>E+GeoIP2FastMin.numIPsv4[F]-1:return'',''
			elif B>E+GeoIP2FastMin.numIPsv6[F]-1:return'',''
			return mainListNamesASN[G],A._int2ip(E)+'/'+str(F)
		except Exception as H:return'',''
	def _ip2int(A,ipaddr):
		B=ipaddr
		try:
			try:return int(A.struct.unpack('>L',A.socket.inet_aton(B))[0])
			except:return int.from_bytes(A.socket.inet_pton(A.socket.AF_INET6,B),byteorder='big')
		except Exception as C:raise GeoIP2FastMin.GeoIPError('Failed at ip2int: %s'%str(C))
	def _int2ip(A,iplong):
		B=iplong
		try:
			if B<GeoIP2FastMin.MAX_IPv4:return A.socket.inet_ntoa(A.struct.pack('>L',B))
			else:return A.socket.inet_ntop(A.socket.AF_INET6,A.binascii.unhexlify(hex(B)[2:].zfill(32)))
		except Exception as C:raise GeoIP2FastMin.GeoIPError('Failed at int2ip: %s'%str(C))
	def set_error_code_private_networks(B,new_value):
		A=new_value;global GEOIP_ECCODE_PRIVATE_NETWORKS
		try:B.error_code_private_networks=A;GEOIP_ECCODE_PRIVATE_NETWORKS=A;return A
		except Exception as C:raise GeoIP2FastMin.GeoIPError('Unable to set a new value for GEOIP_ECCODE_PRIVATE_NETWORKS: %s'%str(C))
	def set_error_code_network_not_found(B,new_value):
		A=new_value;global GEOIP_ECCODE_NETWORK_NOT_FOUND
		try:B.error_code_network_not_found=A;GEOIP_ECCODE_NETWORK_NOT_FOUND=A;return A
		except Exception as C:raise GeoIP2FastMin.GeoIPError('Unable to set a new value for GEOIP_ECCODE_NETWORK_NOT_FOUND: %s'%str(C))
	def lookup(A,ipaddr):
		B=ipaddr;C=A.time.perf_counter()
		try:D=A._ip2int(B)
		except Exception as E:return GeoIP2FastMin.GeoIPDetail(B,country_code=A.error_code_invalid_ip,country_name=GeoIP2FastMin.GEOIP_INVALID_IP_STRING,elapsed_time='%.9f sec'%(A.time.perf_counter()-C))
		try:
			I,J,N,O,P=A._main_index_lookup(D)
			if D>O:return GeoIP2FastMin.GeoIPDetail(ip=B,country_code=A.error_code_network_not_found,country_name=GeoIP2FastMin.GEOIP_NOT_FOUND_STRING,elapsed_time='%.9f sec'%(A.time.perf_counter()-C))
			K=A._int2ip(N)+'/'+str(P);L,M=A._asn_lookup(D)
			if A.country:F,G,H=A._country_lookup(I,J);return GeoIP2FastMin.GeoIPDetail(B,F,G,K,H,L,M,elapsed_time='%.9f sec'%(A.time.perf_counter()-C))
			else:
				F,G,Q,H=A._city_lookup(I,J)
				try:return GeoIP2FastMin.GeoIPDetailCity(B,F,G,Q,K,H,L,M,elapsed_time='%.9f sec'%(A.time.perf_counter()-C))
				except Exception as E:raise Exception(E)
		except Exception as E:return GeoIP2FastMin.GeoIPDetail(ip=B,country_code=A.error_code_lookup_internal_error,country_name=GeoIP2FastMin.GEOIP_INTERNAL_ERROR_STRING,elapsed_time='%.9f sec'%(A.time.perf_counter()-C))
	def get_mem_usage(A):
		' Memory usage in MiB ';D=1024;E=16
		class C(A.ctypes.Structure):_fields_=[('cb',A.ctypes.c_ulong),('PageFaultCount',A.ctypes.c_ulong),('PeakWorkingSetSize',A.ctypes.c_size_t),('WorkingSetSize',A.ctypes.c_size_t),('QuotaPeakPagedPoolUsage',A.ctypes.c_size_t),('QuotaPagedPoolUsage',A.ctypes.c_size_t),('QuotaPeakNonPagedPoolUsage',A.ctypes.c_size_t),('QuotaNonPagedPoolUsage',A.ctypes.c_size_t),('PagefileUsage',A.ctypes.c_size_t),('PeakPagefileUsage',A.ctypes.c_size_t)]
		try:F=A.subprocess.check_output(['ps','-p',str(A.os.getpid()),'-o','rss=']);return float(int(F.strip())/1024)
		except:
			try:
				G=A.ctypes.windll.kernel32.GetCurrentProcessId();H=A.ctypes.windll.kernel32.OpenProcess(D|E,False,G);B=C();B.cb=A.ctypes.sizeof(C)
				if A.ctypes.windll.psapi.GetProcessMemoryInfo(H,A.ctypes.byref(B),A.ctypes.sizeof(B)):I=B.WorkingSetSize;return float(int(I)/1024/1024)
			except:return .0
	def self_test(A,max_ips=30):
		'\n            Do a self-test with some random IPs\n        ';B=[];B.append('x'+A._int2ip(A.random.randint(16777216,3758096383)).replace('.',','));B.append(A._int2ip(A.random.randint(16777216,3758096383))+'/32');B.append(A._int2ip(A.random.randint(397189376,397191423)));B.append(A._int2ip(A.random.choice([A.random.randint(167772160,184549375),A.random.randint(3232235520,3232301055),A.random.randint(2886729728,2887778303)])))
		while len(B)<max_ips:B.append(A._int2ip(A.random.randint(16777216,3758096383)))
		print('\nStarting a self-test with %s randomic IPv4 addresses...\n'%'{:,d}'.format(len(B)));E,F=[],[]
		for D in B:C=A.lookup(D);E.append(float(C.elapsed_time.split(' ')[0]));G=A.lookup(D);F.append(float(G.elapsed_time.split(' ')[0]));print('> '+D.ljust(18)+' '+str(C.country_code).ljust(3)+str(C.country_name[:30]).ljust(30)+' ['+C.elapsed_time+']  Cached > ['+G.elapsed_time+'] '+C.asn_name)
		print('\n\t- Average Lookup Time: %.9f seconds - Average Cached Lookups: %.9f seconds.\n'%(sum(sorted(E)[1:-1])/(len(B)-2),sum(sorted(F)[1:-1])/(len(B)-2)))
if __name__ == "__main__":
    G = GeoIP2FastMin(verbose=True,geoip2fast_data_file="")
    G.self_test()
# GeoIP2Fast v1.0.5

GeoIP2Fast is the fastest GeoIP2 country lookup library. A search takes less than 0.00003 seconds. It has its own data file updated with Maxmind-Geolite2-CSV and is Pure Python!

With it´s own datafile (geoip2fast.dat.gz), can be loaded into memory in ~0.07 seconds and has a small footprint for all data, so you don´t need to make requests to any webservices or connect to an external database.

- With only country support: dat file size of 1.1 Mb with 24Mb of RAM footprint
- With ASN and country support: dat file size of 3.1 Mb with 64Mb of RAM footprint

GeoIP2Fast returns ASN NAME, COUNTRY ISO CODE, COUNTRY NAME and CIDR. There is no external dependencies, you just need the ```geoip2fast.py``` file and the data file ```geoip2fast.dat.gz``` *(updated 19/Sep/2023)*.

To use the ASN data file, just copy the file ```geoip2fast-asn.dat.gz``` over the file ```geoip2fast.dat.gz```. You can create your own file using the ```geoip2dat.py``` file (see instructions below).

```
What's new in v1.0.5 - 20/Sep/2023
- geoip2fast.dat.gz updated with MAXMIND:GeoLite2-Country-CSV_20230919
- geoip2fast-asn.dat.gz updated with MAXMIND:GeoLite2-ASN-Country-CSV_20230919
- faster than ever!!! around ~0.00001 for lookups
- a new option in geoip2dat to create .dat.gz with asn support: --asn-dir
- ASN support - the dat file already has support for ASN of the network 
  ranges. The footprint was incresed to 64Mb. The speed is the same.
- if you want, you can create an another dat file only with country data,
  just use the option --country-dir without the option --asn-dir
- geoip2dat updated too! older versions won't work anymore. Sorry.
- more flowers
```
*The ASN file is 3x larger and takes up too much memory to provide search accuracy. A country block can contain more than 1 ASN, and if we just use the ASN database as a reference, although it has more than 500K network ranges, it only has 60% coverage, while the country database has 440K network ranges, but has more than 99.50% coverage. If we only use the country base as a reference, we may face the problem of a CIDR having more than 1 ASN. We are testing splitting these networks and merging them safely and without reducing coverage for a next version.*

![](https://raw.githubusercontent.com/rabuchaim/geoip2fast/main/images/geoip2fast_selftest.jpg)

![](https://raw.githubusercontent.com/rabuchaim/geoip2fast/main/images/geoip2fast.jpg)

## Installation
```bash
pip install geoip2fast
```
Or cloning from Github
```
git clone https://github.com/rabuchaim/geoip2fast.git
```
## How does it work?

GeoIP2Fast has a datafile **geoip2fast.dat.gz** (3.1Mb with ASN Support). This file is located into the library directory (usually ```/usr/local/lib/python3/dist-packages/geoip2fast```), but you can place this file into the same directory of your application. The library automatically checks both paths, And the directory of your application overlaps the directory of the library. You can use an specific location also. 

The ```bisect()``` function is used together with some ordered lists of integers to search the Network/CountryCode (Yes! an IP address has an integer representation, try to ping this number: ```ping 134744072``` or this ```ping 2130706433``` ).

If GeoIP2Fast does not have a network IP address that was requested, a "not found in database" error will be returned. Unlike many other libraries that when not finding a requested network, gives you the geographical location of the network immediately below. The result is not always correct. 

There are network gaps in the files we use as a source of data, and these missing networks are probably addresses that those responsible have not yet declared their location. Of all almost 4.3 billion IPv4 on the internet, we do not have information on approximately 20 million of them (~0,47%). It must be remembered that the geographical accuracy is the responsibility of the network block owners. If the owner (aka ASN) of the XXX.YYY.ZZZ.D/24 network range declares that his network range is located at "Foo Island", we must believe that an IP address of that network is there.

> *Don't go to Foo Island visit a girl you met on the internet just because you looked up her IP on GeoIP2Fast and the result indicated that she is there.*

## Quick Start

Once the object is created, GeoIP2Fast loads automatically all needed data into memory. The lookup function returns an object called ```GeoIPDetail```. And you can get the values of it's properties just calling the name of proprerty: ```result.ip, result.country_code, result.country_name, result.cidr, result.is_private, result.asn_name and result.elapsed_time```. Or use the function ```to_dict()``` to get the result as a dict. You can get values like ```result.to_dict()['country_code']```


```python
from geoip2fast import GeoIP2Fast

GEOIP = GeoIP2Fast()
result = GEOIP.lookup("200.204.0.10")
print(result)

# to use the country_code property
print(result.country_code)

# to print the ASN name property
print(result.asn_name)

# Before call the function get_hostname(), the property hostname will always be empty.
print("Hostname: "+result.hostname)
result.get_hostname()
print("Hostname: "+result.hostname)

# to work with output as a dict, use the function to_dict()
print(result.to_dict()['country_code'],result.to_dict()['country_name'])

# to check the date of the CSV files used to create the .dat file
print(GEOIP.get_source_info())

# info about internal cache
print(GEOIP.cache_info())

# clear the internal cache
print(GEOIP.clear_cache())

# to see the difference after clear cache
print(GEOIP.cache_info())
```
There is a method to pretty print the result as json.dumps():
```python
>>> result = MyGeoIP.lookup("100.200.100.200")
>>> print(result.pp_json())
{
   "ip": "100.200.100.200",
   "country_code": "US",
   "country_name": "United States",
   "cidr": "100.128.0.0/9",
   "hostname": "",
   "is_private": false,
   "asn_name": "T-MOBILE-AS21928",
   "elapsed_time": "0.000014487 sec"
}
```
or simply: ```result.pp_json(print_result=True)```

To see the start-up line without set ```verbose=True``` :
```python
>>> from geoip2fast import GeoIP2Fast
>>> MyGeoIP = GeoIP2Fast()
>>> MyGeoIP.startup_line_text
'GeoIP2Fast v1.0.5 is ready! geoip2fast.dat.gz loaded with 448562 networks in 0.07333 seconds and using 64.29 MiB.'
```

Private/Reserved networks were included in the database just to be able to provide an answer if one of these IPs is searched. When it happens, the country_code will return "--", the "network name" will be displayed in the country_name and the range of that network will be displayed in the cidr property, and the property **is_private** is setted to **True**.

```python
>>> from geoip2fast import GeoIP2Fast
>>> geoip = GeoIP2Fast(verbose=True)
GeoIP2Fast v1.0.5 is ready! geoip2fast.dat.gz loaded with 448562 networks in 0.06660 seconds and using 45.32 MiB.
>>>
>>> geoip.lookup("10.20.30.40")
{'ip': '10.20.30.40', 'country_code': '--', 'country_name': 'Private Network Class A', 'cidr': '10.0.0.0/8', 'hostname': '', 'is_private': True, 'asn_name': 'IANA.ORG', 'elapsed_time': '0.000094584 sec'}
>>>
>>> geoip.lookup("169.254.10.20")
{'ip': '169.254.10.20', 'country_code': '--', 'country_name': 'APIPA Automatic Priv.IP Addressing', 'cidr': '169.254.0.0/16', 'hostname': '', 'is_private': True, 'asn_name': 'IANA.ORG', 'elapsed_time': '0.000048402 sec'}
```

You can change the behavior of what will be returned in country_code property of "private networks" and for "networks not found":

```python
>>> from geoip2fast import GeoIP2Fast
>>> geoip = GeoIP2Fast(verbose=True)
GeoIP2Fast v1.0.5 is ready! geoip2fast.dat.gz loaded with 448562 networks in 0.06660 seconds and using 45.32 MiB.
>>> geoip.set_error_code_private_networks("@@")
'@@'
>>>
>>> geoip.lookup("10.20.30.40")
{'ip': '10.20.30.40', 'country_code': '@@', 'country_name': 'Private Network Class A', 'cidr': '10.0.0.0/8', 'hostname': '', 'is_private': True, 'asn_name': 'IANA.ORG', 'elapsed_time': '0.000060297 sec'}
>>>
>>> geoip.set_error_code_network_not_found("##")
'##'
>>> geoip.lookup("57.242.128.144")
{'ip': '57.242.128.144', 'country_code': '##', 'country_name': '<not found in database>', 'cidr': '', 'hostname': '', 'is_private': False, 'asn_name': '', 'elapsed_time': '0.000008152 sec'}
>>>
```
You can use it as a CLI also:

```bash
# geoip2fast
GeoIP2Fast v1.0.5 Usage: geoip2fast [-h] [-v] [-d] <ip_address_1>,<ip_address_2>,<ip_address_N>,...
# geoip2fast -v 9.9.9.9,15.20.25.30 -d
GeoIP2Fast v1.0.5 is ready! geoip2fast.dat.gz loaded with 448562 networks in 0.06620 seconds and using 45.28 MiB.
{
   "ip": "9.9.9.9",
   "country_code": "US",
   "country_name": "United States",
   "cidr": "9.9.9.9/32",
   "hostname": "dns9.quad9.net",
   "is_private": false,
   "asn_name": "QUAD9-AS-1",
   "elapsed_time": "0.000041463 sec",
   "elapsed_time_hostname": "0.014539683 sec"
}
{
   "ip": "15.20.25.30",
   "country_code": "US",
   "country_name": "United States",
   "cidr": "15.0.0.0/10",
   "hostname": "<Unknown host>",
   "is_private": false,
   "asn_name": "ATT-IPFR",
   "elapsed_time": "0.000024009 sec"
}
# geoip2fast "2.3.4.5, 4.5.6.7, 8.9.10.11" | jq -r '.country_code'
FR
US
US
# ./geoip2fast.py 8.8.8.8,1.1.1.1,200.204.0.10 -d | jq -r '.hostname'
dns.google
one.one.one.one
resolver1.telesp.net.br
```

## How fast is it?

With an virtual machine with 1 CPU and 4Gb of RAM, we have lookups **lower than 0,00003 seconds**. And if the lookup still in library´s internal cache, the elapsed time goes down to 0,000003 seconds. **GeoIP2Fast can do more than 100K queries per second, per core**. It takes less than 0,07 seconds to load the datafile into memory and get ready to lookup. Use ```verbose=True``` to create the object GeoIP2Fast to see the spent time to start.

Now some tests are included in the geoip2fast.py file. 

```bash
# ./geoip2fast.py -h
GeoIP2Fast v1.0.5 Usage: geoip2fast.py [-h] [-v] [-d] <ip_address_1>,<ip_address_2>,<ip_address_N>,...

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
```

```./geoip2fast.py --self-test```
```bash
# ./geoip2fast.py --self-test
GeoIP2Fast v1.0.4 is ready! geoip2fast.dat.gz loaded with 447695 networks in 0.03532 seconds and using 24.53 MiB.

Starting a self-test...

> 223.130.10.1    -- <network not found in database>   [0.000034988 sec]  Cached > [0.000001427 sec]
> 266.266.266.266    <invalid ip address>              [0.000015505 sec]  Cached > [0.000001393 sec]
> 192,0x0/32         <invalid ip address>              [0.000001101 sec]  Cached > [0.000000881 sec]
> 127.0.0.10      -- Localhost                         [0.000023153 sec]  Cached > [0.000002716 sec] 127.0.0.0/8
> 10.20.30.40     -- Private Network Class A           [0.000012335 sec]  Cached > [0.000001526 sec] 10.0.0.0/8
> 200.204.0.10    BR Brazil                            [0.000014939 sec]  Cached > [0.000002163 sec] 200.204.0.0/14
> 57.242.128.144  -- <network not found in database>   [0.000004927 sec]  Cached > [0.000000707 sec]
> 192.168.10.10   -- Private Network Class C           [0.000009447 sec]  Cached > [0.000001244 sec] 192.168.0.0/16
> 200.200.200.200 BR Brazil                            [0.000004481 sec]  Cached > [0.000001852 sec] 200.200.200.200/32
> 11.22.33.44     US United States                     [0.000005417 sec]  Cached > [0.000001573 sec] 11.0.0.0/10
> 200.147.0.20    BR Brazil                            [0.000004278 sec]  Cached > [0.000001466 sec] 200.144.0.0/14
(.....)
```

```./geoip2fast.py --speed-test```
```bash
# ./geoip2fast.py --speed-test
GeoIP2Fast v1.0.4 is ready! geoip2fast.dat.gz loaded with 447695 networks in 0.03951 seconds and using 23.41 MiB.

Calculating current speed... wait a few seconds please...

Current speed: 136572.73 lookups per second (searched for 1,000,000 IPs in 7.322106013 seconds) [7.32211 sec]
```

```./geoip2fast.py --coverage```
```bash
# ./geoip2fast.py --coverage
GeoIP2Fast v1.0.4 is ready! geoip2fast.dat.gz loaded with 447695 networks in 0.03633 seconds and using 24.64 MiB.

Use the parameter '-v' to see all networks included in you geoip2fast.dat.gz file.

Current IPv4 coverage: 99.53% (4,274,954,633 IPs in 447695 networks) [0.05664 sec]
```
```./geoip2fast.py --coverage -v```
```bash
# ./geoip2fast.py --coverage -v 
GeoIP2Fast v1.0.4 is ready! geoip2fast.dat.gz loaded with 447695 networks in 0.03238 seconds and using 23.35 MiB.

Use the parameter '-v' to see all networks included in you geoip2fast.dat.gz file.

- Network: 0.0.0.0/8           IPs: 16777216   -- Reserved for self identification    0.000054739 sec
- Network: 1.0.0.0/24          IPs: 256        AU Australia                           0.000015415 sec
- Network: 1.0.1.0/24          IPs: 256        CN China                               0.000008385 sec
(.....)
- Network: 223.255.248.0/22    IPs: 1024       HK Hong Kong                           0.000010071 sec
- Network: 223.255.252.0/23    IPs: 512        CN China                               0.000020037 sec
- Network: 223.255.254.0/24    IPs: 256        SG Singapore                           0.000017007 sec
- Network: 223.255.255.0/24    IPs: 256        AU Australia                           0.000013184 sec
- Network: 224.0.0.0/4         IPs: 268435456  -- Reserved Multicast Networks         0.000018643 sec
- Network: 240.0.0.0/4         IPs: 268435456  -- Reserved for future use             0.000018716 sec
- Network: 255.255.255.255/32  IPs: 1          -- Reserved for broadcast              0.000014355 sec

Current IPv4 coverage: 99.53% (4,274,954,633 IPs in 447695 networks) [11.85719 sec]
```

```./geoip2fast.py --missing-ips``` 
```bash
# ./geoip2fast.py --missing-ips
GeoIP2Fast v1.0.4 is ready! geoip2fast.dat.gz loaded with 447695 networks in 0.03497 seconds and using 24.64 MiB.

Searching for missing IPs... (USES 100% OF CPU! - FUNCTION IN TESTS, COULD NOT BE ACCURATE)

From 1.34.65.179     to 1.34.65.179     > Network 1.34.65.180/32     > Missing IPs: 1
From 1.46.23.235     to 1.46.23.235     > Network 1.46.23.236/32     > Missing IPs: 1
From 2.12.211.171    to 2.12.211.171    > Network 2.12.211.172/32    > Missing IPs: 1
(.....)
From 216.238.200.0   to 216.238.207.255 > Network 216.238.208.0/21   > Missing IPs: 2048
From 217.26.216.0    to 217.26.223.255  > Network 217.26.224.0/21    > Missing IPs: 2048
From 217.78.64.0     to 217.78.79.255   > Network 217.78.80.0/20     > Missing IPs: 4096

>>> Valid IP addresses without geo information: 20,012,663 (0.47% of all IPv4) [56.94100 sec]
```
> Some IPs are excluded as described in page "Do Not Sell My Personal Information Requests" at Maxmind website.

## GeoIP2Dat - update geoip2fast.dat.gz file anytime

The updates of geoip2fast.dat.gz file will be published once a week on Github https://github.com/rabuchaim/geoip2fast/. You can also create your own dat file whenever you want, see instructions below.

Download the Geolite2 Country CSV files from Maxmind website and place it into some diretory (in this example, was placed into ```/opt/maxmind/```). Extract this zip file into this directory and run ```geoip2dat``` to see the options.

![](https://raw.githubusercontent.com/rabuchaim/geoip2fast/main/images/geoip2dat01.jpg)

![](https://raw.githubusercontent.com/rabuchaim/geoip2fast/main/images/geoip2dat02.jpg)

The options ```--country-dir``` and ```--output-dir``` are mandatory. Specify the path of extracted files in ```--country-dir``` option. And for ```--output-dir```, put the current path ```./```. 

If you want to add support for ASN data, add the option ```--asn-dir```.

You can choose the language of country locations. The default is ```en```.

After creation of ```geoip2dat.dat.gz``` file, move or copy this file to the directory of your application or to the directory of GeoIP2Fast library. You choose. 

![](https://raw.githubusercontent.com/rabuchaim/geoip2fast/main/images/geoip2dat03.jpg)

**From now you don't depend on anyone to have your data file updated.** There's no point the code being open-source if you're dependent of a single file. 

> *The Philosophers call it 'Libertas'* 


## Create your own GeoIP CLI with 6 lines

1. Create a file named ```geoipcli.py``` and save it in your home directory with the text below:
```python
#!/usr/bin/env python3
import os, sys, geoip2fast
if len(sys.argv) > 1 and sys.argv[1] is not None:
    geoip2fast.GeoIP2Fast().lookup(sys.argv[1]).pp_json(print_result=True)
else:
    print(f"Usage: {os.path.basename(__file__)} <ip_address>")
```
2. Give execution permisstion to your file and create a symbolic link to your new file into ```/usr/sbin``` folder, like this (let's assume that you saved the file into directory /root)
```bash
chmod 750 /root/geoipcli.py
ln -s /root/geoipcli.py /usr/sbin/geoipcli
```
3. Now, you just need to call ```geoipcli``` from any path.
```bash
# geoipcli
Usage: geoipcli <ip_address>

# geoipcli 1.2.3.4
{
   "ip": "1.2.3.4",
   "country_code": "AU",
   "country_name": "Australia",
   "cidr": "1.2.3.0/24",
   "hostname": "",
   "is_private": false,
   "elapsed_time": "0.000019727 sec"
}

# geoipcli x.y.z.w
{
   "ip": "x.y.z.w",
   "country_code": "",
   "country_name": "<invalid ip address>",
   "cidr": "",
   "hostname": "",
   "is_private": false,
   "elapsed_time": "0.000012493 sec"
}

# geoipcli 57.242.128.144
{
   "ip": "57.242.128.144",
   "country_code": "--",
   "country_name": "<network not found in database>",
   "cidr": "",
   "hostname": "",
   "is_private": false,
   "elapsed_time": "0.000019127 sec"
}
```

## GeoIP libraries that inspired me

**GeoIP2Nation - https://pypi.org/project/geoip2nation/** (Created by Avi Asher)

This library uses sqlite3 in-memory tables and use the same search concepts as GeoIP2Fast (based on search by the first´s IPs). Simple and fast! Until this date, the dump file that cames with pip install is corrupted, so use this link to download the complete SQL dump file http://www.ip2nation.com/ip2nation.zip. 

**GeoIP2 - https://pypi.org/project/geoip2/** (created by Maxmind)

This is the best library to work with Maxmind (paid subscription or with the free version). You can use http requests to Maxmind services or work with local Maxmind MMDB binary files. Pretty fast too. Sign-up to have access to all files of the free version https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

**\* Maxmind is a registered trademark** - https://www.maxmind.com

## TO DO list
- a pure-python version for REDIS with a very small footprint (pure protocol, won´t use any REDIS library) **<<< On the way at https://github.com/rabuchaim/geoip2redis**
- a Flask and FastAPI code;
- a mod_geoip2fast for NGINX;
- a better manual, maybe at readthedocs.io;
- a version with cities; **<<< On the way in GeoIP2Fast for Redis https://github.com/rabuchaim/geoip2redis**
- **Done in v1.0.5** - *a version with ASN*.
- **Done in v1.0.2** - *provide a script to update the base. If you have the paid subscription of Maxmind, you can download the files, extract into some directory and use this script to create your own geoip2fast.dat.gz file with the most complete, reliable and updated GeoIP information*.

## Sugestions, feedbacks, bugs, wrong locations...
E-mail me: ricardoabuchaim at gmail.com

# GeoIP2Fast v1.1.10

GeoIP2Fast is the fastest GeoIP2 country/asn lookup library. A search takes less than 0.00003 seconds. It has its own data file updated with Maxmind-Geolite2-CSV, supports IPv4 and IPv6 and is Pure Python!

With it´s own datafile (geoip2fast.dat.gz), can be loaded into memory in ~0.07 seconds and has a small footprint for all data, so you don´t need to make requests to any webservices or connect to an external database.

There are 4 databases included in the installation package:

| Content    | File Name | File Size | Load Time | RAM Footprint | Download Latest |
| ---------- | :---------: | ---------: | --------: | ---------: | :-------------: |
| Country IPv4  | ```geoip2fast.dat.gz``` | 1.1 MiB | ~0.04 sec | ~22.0 MiB | [geoip2fast.dat.gz](https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast.dat.gz) |
| Country IPv4+IPv6  | ```geoip2fast-ipv6.dat.gz``` | 1.1 MiB | ~0.08 sec | ~43.0 MiB | [geoip2fast-ipv6.dat.gz](https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-ipv6.dat.gz) |
| Country+ASN IPv4  | ```geoip2fast-asn.dat.gz```  | 3.1 MiB | ~0.11 sec | ~66.0 MiB | [geoip2fast-asn.dat.gz](https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-asn.dat.gz) |
| Country+ASN IPv4+IPv6  | ```geoip2fast-asn-ipv6.dat.gz``` | 4.0 MiB    | ~0.15 sec    | ~97.0 MiB    | [geoip2fast-asn-ipv6.dat.gz](https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-asn-ipv6.dat.gz) |

GeoIP2Fast returns ASN NAME, COUNTRY ISO CODE, COUNTRY NAME and CIDR. There is no external dependencies, you just need the ```geoip2fast.py``` file and the desired data file ```.dat.gz```. **The lookup speed is the same for any data file**.

**There is also version 1.2.X that returns city names, visit the previous directory [https://github.com/rabuchaim/geoip2fast/](https://github.com/rabuchaim/geoip2fast/)**

```
What's new in v1.1.10 - 22/Nov/2023
- DAT files updated with MAXMIND:GeoLite2-CSV_20231201
- Automatic updates! you can update to the newest dat.gz file via command line or via code
  Using command line:
      geoip2fast --update-all -v

  Using the class GeoIP2Fast:
      from geoip2fast import GeoIP2Fast
      from pprint import pprint
      G = GeoIP2Fast(verbose=True)
      G.get_database_path()
      update_file_result = G.update_file(filename="geoip2fast-asn-ipv6.dat.gz",destination="geoip2fast.dat.gz",verbose=True)
      pprint(update_file_result,sort_dicts=False)
      G.reload_data(verbose=True)
      update_all_result = G.update_all(destination_path="",verbose=True)
      pprint(update_all_result,sort_dicts=False)

```
<br>

![](https://raw.githubusercontent.com/rabuchaim/geoip2fast/main/geoip2fast-legacy/images/geoip2fast_selftest.jpg)

<br>

## Installation
```bash
pip install geoip2fast==1.1.10
```

<br>

## DAT files updates

- You can create your own dat.gz file using [geoip2dat.py](#geoip2dat---update-geoip2fastdatgz-file-anytime) file.
- You can also [download the latest dat files](https://github.com/rabuchaim/geoip2fast/releases/tag/LEGACY) that are updated automatically on Tuesdays and Fridays 
- And you can [update the dat files downloading from our releases repository](#automatic-update-of-datgz-files), via code or via command line.

<br>

## How does it work?

GeoIP2Fast has 4 datafiles included. Tha main file is ```geoip2fast.dat.gz``` with support Country lookups and only IPv4. Usually, these files are located into the library directory (```/usr/local/lib/python3/dist-packages/geoip2fast```), but you can place it into the same directory of your application. The library automatically checks both paths, And the directory of your application overlaps the directory of the library. You can use an specific location also. 

The ```bisect()``` function is used together with some ordered lists of integers to search the Network/CountryCode (Yes! an IP address has an integer representation, try to ping this number: ```ping 134744072``` or this ```ping 2130706433``` ).

If GeoIP2Fast does not have a network IP address that was requested, a "not found in database" error will be returned. Unlike many other libraries that when not finding a requested network, gives you the geographical location of the network immediately below. The result is not always correct. 

There are network gaps in the files we use as a source of data, and these missing networks are probably addresses that those responsible have not yet declared their location. Of all almost 4.3 billion IPv4 on the internet, we do not have information on approximately 15 million of them (~0,35%). It must be remembered that the geographical accuracy is the responsibility of the network block owners. If the owner (aka ASN) of the XXX.YYY.ZZZ.D/24 network range declares that his network range is located at "Foo Island", we must believe that an IP address of that network is there.

> *Don't go to Foo Island visit a girl you met on the internet just because you looked up her IP on GeoIP2Fast and the result indicated that she is there.*

<br>

## Quick Start

Once the object is created, GeoIP2Fast loads automatically all needed data into memory. The lookup function returns an object called ```GeoIPDetail```. And you can get the values of it's properties just calling the name of proprerty: ```result.ip, result.country_code, result.country_name, result.cidr, result.is_private, result.asn_name``` and ```result.elapsed_time```. Or use the function ```to_dict()``` to get the result as a dict. You can get values like ```result.to_dict()['country_code']```

At the moment of creation, you can define which data you want to use. Country+IPv4, Country+IPv4+IPv6, Country+ASN+IPv4 or Country+ASN+IPv4+IPv6. If don´t specify any file, the default ```geoip2fast.dat.gz``` will be used.


```python
from geoip2fast import GeoIP2Fast

GEOIP = GeoIP2Fast()
print(GEOIP.get_database_path())

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
'GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 433468 networks in 0.04153 seconds and using 23.75 MiB.'
```

If you call geoip2fast from command line, it´s only use ```geoip2fast.dat.gz``` file, so if you want more data like ASN or IPv6 support, you have to copy the respective file over ```geoip2fast.dat.gz``` file. If you are using GeoIP2Fast as a Python library, you don´t need to rename or copy any file, you can load the desired data file in the moment of object creation. The library first looks for the given file in the current directory and then in the library directory. If desired, you can directly specify the path. 

```python
>>> from geoip2fast import GeoIP2Fast
>>> geoip = GeoIP2Fast(geoip2fast_data_file="geoip2fast-asn.dat.gz",verbose=True)
GeoIP2Fast v1.1.10 is ready! geoip2fast-asn.dat.gz loaded with 456271 networks in 0.09355 seconds and using 66.99 MiB.
>>> geoip.get_database_path()
'/usr/local/lib/python3.11/dist-packages/geoip2fast/geoip2fast-asn.dat.gz'
>>>
>>> geoip.lookup("2a02:26f0:6d00:5bc::b63")
{'ip': '2a02:26f0:6d00:5bc::b63', 'country_code': 'NL', 'country_name': 'Netherlands', 'cidr': '2a02:26f0:6d00::/40', 'hostname': '', 'is_private': False, 'asn_name': 'Akamai International B.V.', 'elapsed_time': '0.000600145 sec'}
>>>
>>> geoip = GeoIP2Fast(geoip2fast_data_file="/opt/maxmind/geoip2fast-asn.dat.gz",verbose=True)
GeoIP2Fast v1.1.10 is ready! geoip2fast-asn.dat.gz loaded with 456271 networks in 0.11666 seconds and using 67.05 MiB.
>>> geoip.get_database_path()
'/opt/maxmind/geoip2fast-asn.dat.gz'
```

Private/Reserved networks were included in the database just to be able to provide an answer if one of these IPs is searched. When it happens, the country_code will return "--", the "network name" will be displayed in the country_name and the range of that network will be displayed in the cidr property, and the property **is_private** is setted to **True**.

```python
>>> from geoip2fast import GeoIP2Fast
>>> geoip = GeoIP2Fast(verbose=True)
GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 433468 networks in 0.04153 seconds and using 23.75 MiB.
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
GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 433468 networks in 0.04153 seconds and using 23.75 MiB.
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

<br>

## How fast is it?

With an virtual machine with 1 CPU and 4Gb of RAM, we have lookups **lower than 0,00003 seconds**. And if the lookup still in library´s internal cache, the elapsed time goes down to 0,000003 seconds. **GeoIP2Fast can do more than 100K queries per second, per core**. It takes less than 0,07 seconds to load the datafile into memory and get ready to lookup. Use ```verbose=True``` to create the object GeoIP2Fast to see the spent time to start.

```geoip2fast --self-test```
```bash
# geoip2fast --self-test
GeoIP2Fast v1.1.19 is ready! geoip2fast.dat.gz loaded with 433468 networks in 0.04153 seconds and using 23.75 MiB.

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

```geoip2fast --speed-test```
```bash
# geoip2fast --speed-test
GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 433468 networks in 0.04153 seconds and using 23.75 MiB.

Calculating current speed... wait a few seconds please...

Current speed: 136572.73 lookups per second (searched for 1,000,000 IPs in 7.322106013 seconds) [7.32211 sec]
```

```geoip2fast --coverage```
```bash
# geoip2fast --coverage
GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 748074 networks in 0.15510 seconds and using 98.30 MiB.

Use the parameter '-v' to see all networks included in your /opt/pypi-geoip2fast/git-geoip2fast/geoip2fast/geoip2fast.dat.gz file.

Current IPv4 coverage: 99.64% (4,279,396,946 IPv4 in 453615 networks) [0.12512 sec]
Current IPv6 coverage: 0.40% (1,364,425,945,439,630,011,748,628,700,499,804,160 IPv6 in 294459 networks) [0.12518 sec]
```
```geoip2fast --coverage -v```
```bash
# geoip2fast --coverage -v
GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 748074 networks in 0.15510 seconds and using 98.30 MiB.

Use the parameter '-v' to see all networks included in your /opt/pypi-geoip2fast/git-geoip2fast/geoip2fast/geoip2fast.dat.gz file.

- Network: 0.0.0.0/8           IPs: 16777216   -- Reserved for self identification    0.000128794 sec
- Network: 1.0.0.0/24          IPs: 256        AU Australia                           0.000073830 sec
- Network: 1.0.1.0/24          IPs: 256        CN China                               0.000084977 sec
- Network: 1.0.2.0/23          IPs: 512        CN China                               0.000015769 sec
- Network: 1.0.4.0/22          IPs: 1024       AU Australia                           0.000015369 sec
- Network: 1.0.8.0/21          IPs: 2048       CN China                               0.000023131 sec
- Network: 1.0.16.0/20         IPs: 4096       JP Japan                               0.000095840 sec
(.....)
- Network: 2c0f:ffb8::/32      IPs: 79228162514264337593543950336 SD Sudan                               0.000018255 sec
- Network: 2c0f:ffc0::/32      IPs: 79228162514264337593543950336 ZA South Africa                        0.000032078 sec
- Network: 2c0f:ffc8::/32      IPs: 79228162514264337593543950336 ZA South Africa                        0.000031547 sec
- Network: 2c0f:ffd0::/32      IPs: 79228162514264337593543950336 ZA South Africa                        0.000022423 sec
- Network: 2c0f:ffd8::/32      IPs: 79228162514264337593543950336 ZA South Africa                        0.000012151 sec
- Network: 2c0f:ffe8::/32      IPs: 79228162514264337593543950336 NG Nigeria                             0.000010622 sec
- Network: 2c0f:fff0::/32      IPs: 79228162514264337593543950336 NG Nigeria                             0.000017496 sec
- Network: fd00::/8            IPs: 1329227995784915872903807060280344576 -- Reserved for Unique Local Addresses 0.000033054 sec

Current IPv4 coverage: 99.64% (4,279,396,946 IPv4 in 453615 networks) [18.88599 sec]
Current IPv6 coverage: 0.40% (1,364,425,945,439,630,011,748,628,700,499,804,160 IPv6 in 294459 networks) [18.88601 sec]
```

```geoip2fast --missing-ips``` 
```bash
# geoip2fast --missing-ips
GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 748074 networks in 0.15510 seconds and using 98.30 MiB.

Searching for missing IPs... 

From 1.34.65.179     to 1.34.65.179     > Network 1.34.65.180/32     > Missing IPs: 1
From 1.46.23.235     to 1.46.23.235     > Network 1.46.23.236/32     > Missing IPs: 1
From 2.12.211.171    to 2.12.211.171    > Network 2.12.211.172/32    > Missing IPs: 1
(.....)
From 216.238.200.0   to 216.238.207.255 > Network 216.238.208.0/21   > Missing IPs: 2048
From 217.26.216.0    to 217.26.223.255  > Network 217.26.224.0/21    > Missing IPs: 2048
From 217.78.64.0     to 217.78.79.255   > Network 217.78.80.0/20     > Missing IPs: 4096

>>> Valid IP addresses without geo information: 15,169,195 (0.35% of all IPv4) [44.30283 sec]
```

> Some IPs are excluded as described in page "Do Not Sell My Personal Information Requests" at Maxmind website.

<br>

## You can use it as a CLI

```bash
# geoip2fast -h
GeoIP2Fast v1.1.3 Usage: geoip2fast [-h] [-v] [-d] <ip_address_1>,<ip_address_2>,<ip_address_N>,...

Tests parameters:
  --self-test         Starts a self-test with some randomic IP addresses.
  --speed-test        Do a speed test with 1 million on randomic IP addresses.
  --random-test       Start a test with 1.000.000 of randomic IPs and calculate a lookup average time.

  --coverage [-v]     Shows a statistic of how many IPs are covered by current dat file.
  --missing-ips [-v]  Print all IP networks that doesn't have geo information.

More options:
  -d                  Resolve the DNS of given IP address.
  -h                  Show this help text.
  -v                  Verbose mode.
  -vvv                Shows the location of current dat file.
```

```bash
# geoip2fast
GeoIP2Fast v1.1.3 Usage: geoip2fast [-h] [-v] [-d] <ip_address_1>,<ip_address_2>,<ip_address_N>,...
# geoip2fast -v 9.9.9.9,15.20.25.30 -d
GeoIP2Fast v1.1.3 is ready! geoip2fast.dat.gz loaded with 433468 networks in 0.10803 seconds and using 65.61 MiB.
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
<br>

## GeoIP2Dat - update geoip2fast.dat.gz file anytime

The updates of geoip2fast.dat.gz file will be published twice a week on Github https://github.com/rabuchaim/geoip2fast/releases/tag/LEGACY. You can also create your own dat file whenever you want, see instructions below.

Download the Geolite2 Country CSV files from Maxmind website and place it into some diretory (in this example, was placed into ```/opt/maxmind/```). Extract this zip file into this directory and run ```geoip2dat``` to see the options.

![](https://raw.githubusercontent.com/rabuchaim/geoip2fast/main/geoip2fast-legacy/images/geoip2dat01.jpg)

![](https://raw.githubusercontent.com/rabuchaim/geoip2fast/main/geoip2fast-legacy/images/geoip2dat02.jpg)

The options ```--country-dir``` and ```--output-dir``` are mandatory. Specify the path of extracted files in ```--country-dir``` option. And for ```--output-dir```, put the current path ```./```. 

If you want to add support for ASN data, add the option ```--asn-dir```. And if you want to add IPv6 support, just add ```--with-ipv6``` to your command line.

You can choose the language of country locations. The default is ```en```.

After creation of ```geoip2dat.dat.gz``` file, move or copy this file to the directory of your application or to the directory of GeoIP2Fast library. You choose. 

![](https://raw.githubusercontent.com/rabuchaim/geoip2fast/main/geoip2fast-legacy/images/geoip2dat03.jpg)

**From now you don't depend on anyone to have your data file updated.** There's no point the code being open-source if you're dependent of a single file. 

> *The Philosophers call it 'Libertas'* 

<br>

## Automatic update of dat.gz files

From version 1.1.10 onwards, it is now possible to update the dat.gz files that were made available in our releases repository. You can update via command line or via code.

- Download the file "geoip2fast-asn-ipv6.dat.gz" and save it as "geoip2fast.dat.gz":

```python
>>> from geoip2fast import GeoIP2Fast
>>> G = GeoIP2Fast(verbose=True)
GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 459270 networks in 0.03297 seconds and using 25.12 MiB.
>>> update_result = G.update_file('geoip2fast-asn-ipv6.dat.gz','geoip2fast.dat.gz',verbose=False)
>>> G.reload_data(verbose=True)
GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 753871 networks in 0.12917 seconds and using 113.54 MiBTrue
>>>
```

- Update all files:

```python
>>> from geoip2fast import GeoIP2Fast
>>> G = GeoIP2Fast()
>>> update_result = G.update_all(verbose=True)
- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
- Downloading geoip2fast.dat.gz... 100.00% of 1.06 MiB [6.51 MiB/s] [0.163 sec]
- File saved to: /opt/geoip2fast/geoip2fast-legacy/geoip2fast/geoip2fast.dat.gz

- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-ipv6.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
- Downloading geoip2fast-ipv6.dat.gz... 100.00% of 1.73 MiB [9.66 MiB/s] [0.179 sec]
- File saved to: /opt/geoip2fast/geoip2fast-legacy/geoip2fast/geoip2fast-ipv6.dat.gz

- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-asn.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
- Downloading geoip2fast-asn.dat.gz... 100.00% of 3.06 MiB [8.63 MiB/s] [0.354 sec]
- File saved to: /opt/geoip2fast/geoip2fast-legacy/geoip2fast/geoip2fast-asn.dat.gz

- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-asn-ipv6.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
- Downloading geoip2fast-asn-ipv6.dat.gz... 100.00% of 4.09 MiB [7.66 MiB/s] [0.534 sec]
- File saved to: /opt/geoip2fast/geoip2fast-legacy/geoip2fast/geoip2fast-asn-ipv6.dat.gz
>>>
```
- Update all files silently and verify if there are errors:
```python
>>> from geoip2fast import GeoIP2Fast
>>> G = GeoIP2Fast()
>>> update_result = G.update_all(verbose=False)
>>> errors_result = [item for item in update_result if item['error'] is not None]
>>> print(errors_result)
[]
```
- You can change the update URL if you want.
```
>>> G.get_update_url()
'https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/'
>>> G.set_update_url("https://github.com/YOUR_OWN_REPO/YOUR_PROJECT/releases/download/latest/")
True
>>> G.get_update_url()
'https://github.com/YOUR_OWN_REPO/YOUR_PROJECT/releases/download/latest/'
>>>
```
- Update the file "geoip2fast-asn-ipv6.dat.gz" and overwrite "geoip2fast.dat.gz" and print the result. 
```python
>>> from geoip2fast import GeoIP2Fast
>>> G = GeoIP2Fast(verbose=True)
GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 459270 networks in 0.04414 seconds and using 5.02 MiB.
>>> update_result = G.update_file('geoip2fast-asn-ipv6.dat.gz','geoip2fast.dat.gz',verbose=False)
>>> from pprint import pprint as pp
>>> pp(update_result,sort_dicts=False)
{'error': None,
 'url': 'https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-asn-ipv6.dat.gz',
 'remote_filename': 'geoip2fast-asn-ipv6.dat.gz',
 'last_modified_date': 'Mon, 27 Nov 2023 02:40:08 GMT',
 'file_size': 4289564,
 'file_destination': '/opt/geoip2fast/geoip2fast-legacy/geoip2fast/geoip2fast.dat.gz',
 'average_download_speed': '4.09 MiB/sec',
 'elapsed_time': '0.587267'}
>>>
>>> G.reload_data(verbose=True)
GeoIP2Fast v1.1.10 is ready! geoip2fast.dat.gz loaded with 753871 networks in 0.12245 seconds and using 57.55 MiB.
>>>

```
- **Using the command line, no message will be displayed on the console unless you use the -v parameter**
- Update all files via command line and save them in '/tmp/' directory:
```bash
# geoip2fast --update-all --dest /tmp/ -v
- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
- Downloading geoip2fast.dat.gz... 100.00% of 1.06 MiB [10.41 MiB/s] [0.102 sec]
- File saved to: /tmp/geoip2fast.dat.gz

- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-ipv6.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
- Downloading geoip2fast-ipv6.dat.gz... 100.00% of 1.73 MiB [9.46 MiB/s] [0.183 sec]
- File saved to: /tmp/geoip2fast-ipv6.dat.gz

- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-asn.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
- Downloading geoip2fast-asn.dat.gz... 100.00% of 3.06 MiB [7.06 MiB/s] [0.433 sec]
- File saved to: /tmp/geoip2fast-asn.dat.gz

- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-asn-ipv6.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
- Downloading geoip2fast-asn-ipv6.dat.gz... 100.00% of 4.09 MiB [7.31 MiB/s] [0.560 sec]
- File saved to: /tmp/geoip2fast-asn-ipv6.dat.gz
```
- Update the file "geoip2fast-asn-ipv6.dat.gz" and overwrite "geoip2fast.dat.gz"
```bash
# geoip2fast --update-file geoip2fast-asn-ipv6.dat.gz --dest geoip2fast.dat.gz -v
- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast-asn-ipv6.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
- Downloading geoip2fast-asn-ipv6.dat.gz... 100.00% of 4.09 MiB [4.29 MiB/s] [0.954 sec]
- File saved to: /opt/geoip2fast/geoip2fast-legacy/geoip2fast/geoip2fast.dat.gz
```
- Update the file "geoip2fast.dat.gz" and save it in the library path
```bash
# geoip2fast --update-file geoip2fast.dat.gz -v
- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
- Downloading geoip2fast.dat.gz... 100.00% of 1.06 MiB [9.54 MiB/s] [0.111 sec]
- File saved to: /opt/geoip2fast/geoip2fast-legacy/geoip2fast/geoip2fast.dat.gz
```
- Update the file "geoip2fast.dat.gz" and save it in the library path

```bash
# geoip2fast --update-file geoip2fast.dat.gz
# echo $?
0
```
- An example of a simulated download failure: 
```bash
# geoip2fast.py --update-file geoip2fast.dat.gz -v
- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/aLEGACY_v1.1.9/geoip2fast.dat.gz
- Error: HTTP Error 404: Not Found - https://github.com/rabuchaim/geoip2fast/releases/download/aLEGACY_v1.1.9/geoip2fast.dat.gz
# echo $?
1
```
```bash
# geoip2fast.py --update-file geoip2fast.dat.gz -v
- Opening URL https://github.com/rabuchaim/geoip2fast/releases/download/LEGACY/geoip2fast.dat.gz
- Last Modified Date: Mon, 27 Nov 2023 02:40:08 GMT
PermissionError: [Errno 1] Operation not permitted: '/opt/geoip2fast/geoip2fast-legacy/geoip2fast/geoip2fast.dat.gz'
# echo $?
1
```
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

This library uses sqlite3 in-memory tables and use the same search concepts as GeoIP2Fast (based on search by the first´s IPs). Simple and fast! Unfortunately it is no longer being updated and that is why I developed GeoIP2Fast.

**GeoIP2 - https://pypi.org/project/geoip2/** (created by Maxmind)

This is the best library to work with Maxmind (paid subscription or with the free version). You can use http requests to Maxmind services or work with local Maxmind MMDB binary files. Pretty fast too. Sign-up to have access to all files of the free version https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

**\* Maxmind is a registered trademark** - https://www.maxmind.com

## TO DO list
- a pure-python version for REDIS with a very small footprint (pure protocol, won´t use any REDIS library) **<<< On the way at https://github.com/rabuchaim/geoip2redis**
- a GeoIP Server; **<<< On the way a docker container, your own GeoIP server inside your network. With rest API or socket (super fast)**
- a mod_geoip2fast for NGINX;
- a better manual, maybe at readthedocs.io;
- **Done in v1.1.10/v1.2.1** - automatic update of dat.gz files;
- **Done in v1.2.0** - a version with cities;
- **Done in v1.1.0** - *IPv6 support*.
- **Done in v1.0.5** - *a version with ASN*.
- **Done in v1.0.2** - *provide a script to update the base. If you have the paid subscription of Maxmind, you can download the files, extract into some directory and use this script to create your own geoip2fast.dat.gz file with the most complete, reliable and updated GeoIP information*.

## Sugestions, feedbacks, bugs, wrong locations...
E-mail me: ricardoabuchaim at gmail.com

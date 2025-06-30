#!/usr/bin/env python3

import socket
import concurrent.futures
import argparse
import time
from datetime import datetime
import sys
import os
import random
import readline
from threading import Thread, Lock, Timer
import signal
import json
from tabulate import tabulate
from tqdm import tqdm
import dns.resolver
import ipaddress
import re
import csv
import xml.etree.ElementTree as ET
import requests
from bs4 import BeautifulSoup
import socks
import socket
import geoip2.database
from fpdf import FPDF
import threading
from flask import Flask, jsonify, request
import whois
import subprocess
from urllib.parse import urlparse
import ssl


api_app = Flask(__name__)
api_mode = False

class MatrixColors:
    class Fore:
        BLACK = '\033[30m'
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        MAGENTA = '\033[35m'
        CYAN = '\033[36m'
        WHITE = '\033[37m'
        BRIGHT_BLACK = '\033[90m'
        BRIGHT_RED = '\033[91m'
        BRIGHT_GREEN = '\033[92m'
        BRIGHT_YELLOW = '\033[93m'
        BRIGHT_BLUE = '\033[94m'
        BRIGHT_MAGENTA = '\033[95m'
        BRIGHT_CYAN = '\033[96m'
        BRIGHT_WHITE = '\033[97m'
    
    class Style:
        RESET = '\033[0m'
        BOLD = '\033[1m'
        DIM = '\033[2m'
        ITALIC = '\033[3m'
        UNDERLINE = '\033[4m'
        BLINK = '\033[5m'
        REVERSE = '\033[7m'
        HIDDEN = '\033[8m'


CONFIG = {
    'max_threads': 500,
    'default_timeout': 3,
    'geoip_db_path': 'GeoLite2-City.mmdb',
    'tor_proxy': 'socks5://127.0.0.1:9050',
    'shodan_api_key': '',
    'virustotal_api_key': '',
    'wafw00f_path': 'wafw00f',
    'scheduled_scans': {}
}


VULN_DB = {
    'vsftpd 2.3.4': {'CVE': 'CVE-2011-2523', 'exploit': 'vsftpd 2.3.4 Backdoor Command Execution'},
    'ProFTPd 1.3.3c': {'CVE': 'CVE-2010-4221', 'exploit': 'ProFTPd 1.3.3c Remote Code Execution'},
    'OpenSSH 7.2p2': {'CVE': 'CVE-2016-8858', 'exploit': 'OpenSSH 7.2p2 Privilege Escalation'},
    'Apache 2.4.49': {'CVE': 'CVE-2021-41773', 'exploit': 'Apache 2.4.49 Path Traversal'},
    'WordPress': {'CVE': 'CVE-2021-29447', 'exploit': 'WordPress XXE Vulnerability'},
}


DEVICE_FINGERPRINTS = {
    'router': {'ports': [80, 443, 7547], 'ttl_range': (30, 64)},
    'webcam': {'ports': [80, 554, 9000], 'ttl_range': (60, 120)},
    'iot': {'ports': [8080, 8888, 1883], 'ttl_range': (30, 64)},
    'nas': {'ports': [21, 22, 443, 5000], 'ttl_range': (60, 120)},
}


WAF_FINGERPRINTS = {
    'Cloudflare': {'headers': ['server', 'cf-ray'], 'patterns': ['cloudflare']},
    'DDoS-Guard': {'headers': ['server'], 'patterns': ['ddos-guard']},
    'Akamai': {'headers': ['server'], 'patterns': ['akamai']},
    'Incapsula': {'headers': ['x-iinfo'], 'patterns': ['incapsula']},
}

def show_matrix_banner():
    matrix_chars = "01アイウエオカキクケコサシスセソタチツテトナニヌネノハヒフヘホマミムメモヤユヨラリルレロワヲン"
    
    def matrix_effect():
        while not stop_threads:
            print(random.choice(matrix_chars), end='', flush=True)
            time.sleep(0.01)
    
    stop_threads = False
    matrix_thread = Thread(target=matrix_effect)
    matrix_thread.daemon = True
    matrix_thread.start()
    
    print(f"""{MatrixColors.Fore.BRIGHT_GREEN}{MatrixColors.Style.BOLD}
    ██╗██████╗      ██████╗██████╗ ██╗  ██╗
    ██║██╔══██╗    ██╔════╝██╔══██╗██║  ██║
    ██║██████╔╝    ██║     ██████╔╝███████║
    ██║██╔══██╗    ██║     ██╔═══╝ ██╔══██║
    ██║██║  ██║    ╚██████╗██║     ██║  ██║
    ╚═╝╚═╝  ╚═╝     ╚═════╝╚═╝     ╚═╝  ╚═╝
    
    {MatrixColors.Fore.BRIGHT_CYAN}
    ██████╗ ███████╗██████╗ ████████╗
    ██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
    ██████╔╝█████╗  ██████╔╝   ██║   
    ██╔═══╝ ██╔══╝  ██╔═══╝    ██║   
    ██║     ███████╗██║        ██║   
    ╚═╝     ╚══════╝╚═╝        ╚═╝   
    {MatrixColors.Fore.BRIGHT_MAGENTA}
    iRC-PT Matrix Scanner v9.0 Pro
    Iranian Cybers Team
    {MatrixColors.Style.RESET}""")
    
    time.sleep(3)
    stop_threads = True
    matrix_thread.join()
    os.system('clear' if os.name == 'posix' else 'cls')

PORT_SERVICES = {
    1: "TCPMUX", 5: "RJE", 7: "ECHO", 9: "DISCARD", 11: "SYSTAT", 13: "DAYTIME",
    17: "QOTD", 18: "MSP", 19: "CHARGEN", 20: "FTP-DATA", 21: "FTP", 22: "SSH",
    23: "TELNET", 25: "SMTP", 37: "TIME", 42: "NAMESERVER", 43: "WHOIS",
    49: "TACACS", 53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 70: "GOPHER",
    79: "FINGER", 80: "HTTP", 88: "KERBEROS", 102: "ISO-TSAP", 110: "POP3",
    115: "SFTP", 118: "SQLSERV", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NETBIOS-NS", 138: "NETBIOS-DGM", 139: "NETBIOS-SSN", 143: "IMAP",
    161: "SNMP", 162: "SNMPTRAP", 179: "BGP", 194: "IRC", 201: "AT-RTMP",
    264: "BGMP", 318: "TSP", 381: "HP-OPENVIEW", 382: "HP-OPENVIEW",
    383: "HP-OPENVIEW", 389: "LDAP", 411: "DIRECTCONNECT", 412: "DIRECTCONNECT",
    443: "HTTPS", 445: "MICROSOFT-DS", 464: "KERBEROS", 465: "SMTPS",
    497: "RETROSPECT", 500: "ISAKMP", 512: "EXEC", 513: "LOGIN", 514: "SHELL",
    515: "PRINTER", 520: "RIP", 521: "RIPNG", 540: "UUCP", 543: "KLOGIN",
    544: "KSHELL", 546: "DHCP-CLIENT", 547: "DHCP-SERVER", 548: "AFP",
    554: "RTSP", 563: "NNTPS", 587: "SUBMISSION", 591: "FILEMAKER",
    593: "MS-RPC", 631: "IPP", 636: "LDAPS", 639: "MSDP", 646: "LDP",
    647: "DHCP-FAILOVER", 648: "RRP", 652: "DTCP", 654: "AODV",
    658: "MAC-SRVR-ADMIN", 666: "DOOM", 691: "MS-EXCHANGE",
    692: "HYPERWAVE-ISP", 695: "IEEE-MMS-SSL", 698: "OLSR",
    699: "ACCESS-NETWORK", 700: "EPP", 701: "LMP", 702: "IRIS-BEEP",
    706: "SILC", 711: "CISCO-TDP", 712: "TBRPF", 720: "NETVIEWDM1",
    721: "NETVIEWDM2", 722: "NETVIEWDM3", 726: "NETVIEWDM6",
    729: "NETVIEWDM9", 730: "NETVIEWDM10", 731: "NETVIEWDM11",
    740: "NETSCREEN-REDIR", 741: "NETSCREEN-GLOBAL", 742: "NETSCREEN-ALARM",
    744: "FLEXLM", 747: "Fujitsu Device Control", 748: "RIS",
    749: "KERBEROS-ADM", 750: "KERBEROS-IV", 751: "PUMP", 752: "QRH",
    753: "RRH", 754: "TELL", 758: "NLOGIN", 759: "CON", 760: "NS",
    761: "RXE", 762: "QUOTAD", 763: "CYCLESERV", 764: "OMSERV",
    765: "WEBSTER", 767: "PHONEBOOK", 769: "VID", 770: "CADLOCK",
    771: "RTIP", 772: "CYCLESERV2", 773: "SUBMIT", 774: "RPASSWD",
    775: "ENTOMB", 776: "WALLD", 777: "ENDPOINT", 780: "WPGS",
    781: "HP-COLORLASERJET", 800: "MDBS-DAEMON", 801: "DEVICE",
    808: "CCPROXY", 843: "ADOBE-FLASH", 873: "RSYNC", 888: "DDNS",
    902: "VMWARE-AUTHD", 903: "VMWARE-INSTALL", 989: "FTPS-DATA",
    990: "FTPS", 991: "NAS", 992: "TELNETS", 993: "IMAPS", 994: "IRCS",
    995: "POP3S", 1080: "SOCKS", 1099: "RMI-REGISTRY", 1109: "KERBEROS-POP",
    1167: "PHONE", 1194: "OPENVPN", 1214: "KAZAA", 1241: "NESSUS",
    1311: "Dell OpenManage", 1337: "WASTE", 1352: "LOTUSNOTES",
    1433: "MS-SQL", 1434: "MS-SQL-M", 1512: "WINS", 1521: "ORACLE",
    1589: "CITRIX-ICA", 1723: "PPTP", 1725: "STEAM", 1741: "CISCO-MGCP",
    1755: "MS-MEDIA-SERVER", 1761: "LANDESK", 1801: "MSMQ", 1812: "RADIUS",
    1813: "RADIUS-ACCT", 1863: "MSN", 1900: "UPNP", 1935: "RTMP",
    1984: "BIGBROTHER", 2000: "CISCO-SCCP", 2001: "DC", 2002: "GLORYTUN",
    2030: "ORACLE-EM", 2049: "NFS", 2082: "CPANEL", 2083: "CPANEL-SSL",
    2086: "WHM", 2087: "WHM-SSL", 2095: "CPANEL-WEBMAIL",
    2096: "CPANEL-WEBMAIL-SSL", 2100: "AMIGA", 2222: "DIRECTADMIN",
    2302: "ARMAGETRON", 2483: "ORACLE-DB", 2484: "ORACLE-DB-SSL",
    3000: "REDIS", 3128: "SQUID", 3260: "ISCSI", 3306: "MYSQL",
    3389: "RDP", 3690: "SVN", 4000: "REMOTEANYTHING", 4040: "TOR-SOCKS",
    4064: "IRSSI", 4100: "WATCHGUARD", 4333: "MSSQL-ADMIN", 4444: "METASPLOIT",
    4500: "IPSEC-NAT-T", 4567: "SINUS", 4662: "EMULE", 4672: "EMULE-KAD",
    4899: "RADMIN", 5000: "UPNP", 5001: "SIP", 5009: "AIRPORT-ADMIN",
    5050: "YAHOO-MESSENGER", 5060: "SIP", 5190: "AIM", 5222: "XMPP-CLIENT",
    5223: "XMPP-CLIENT-SSL", 5228: "ANDROID", 5353: "MDNS", 5432: "POSTGRESQL",
    5500: "VNC-HTTP", 5555: "ANDROID-DEBUG", 5631: "PCANYWHERE", 5666: "NRPE",
    5800: "VNC-HTTP", 5900: "VNC", 5938: "TEAMVIEWER", 6000: "X11",
    6001: "X11-1", 6379: "REDIS", 6667: "IRC", 6697: "IRC-SSL",
    6881: "BITTORRENT", 6969: "BITTORRENT-TRACKER", 7000: "AFS",
    7070: "REALSERVER", 7547: "CWMP", 7777: "GAME", 8000: "HTTP-ALT",
    8008: "HTTP-ALT", 8080: "HTTP-PROXY", 8081: "HTTP-PROXY-1",
    8088: "RADIUS", 8090: "HTTP-ALT", 8118: "PRIVOXY", 8123: "POLIPO",
    8200: "VMWARE", 8222: "VMWARE", 8443: "HTTPS-ALT", 8888: "HTTP-ALT",
    9000: "PHPLDAPADMIN", 9001: "TOR", 9090: "WEBSM", 9091: "TRANSMISSION",
    9100: "JETDIRECT", 9200: "ELASTICSEARCH", 9300: "ELASTICSEARCH",
    9418: "GIT", 9535: "MUNIN", 9800: "WEBDAV", 9898: "MONITORIX",
    9988: "RBOT", 9999: "URD", 10000: "WEBMIN", 11211: "MEMCACHED",
    12345: "NETBUS", 18080: "MONGO", 20000: "DNP3", 27017: "MONGODB",
    31337: "BACKORIFICE", 49152: "SUPERVISOR", 50000: "DB2", 50030: "HADOOP",
    50060: "HADOOP", 50070: "HADOOP", 50075: "HADOOP", 50090: "HADOOP"
}

NETWORK_PROTOCOLS = {
    "tcp": socket.SOCK_STREAM,
    "udp": socket.SOCK_DGRAM
}

class IRCPTScanner:
    def __init__(self):
        self.target = None
        self.target_ip = None
        self.ports = None
        self.threads = 200
        self.timeout = 2
        self.open_ports = []
        self.scanning = False
        self.lock = Lock()
        self.command_history = []
        self.silent_mode = False
        self.scan_types = {
            "quick": (1, 1024),
            "normal": (1, 49152),
            "full": (1, 65535)
        }
        self.protocol = "tcp"
        self.service_versions = {}
        self.os_guesses = []
        self.scan_start_time = None
        self.scan_end_time = None
        self.waf_detected = None
        self.device_type = None
        self.geo_info = None
        self.dns_records = {}
        self.vulnerabilities = []
        self.honeypot_indicators = []
        self.proxy_config = None
        
    def resolve_target(self, target):
        try:
            try:
                ip_obj = ipaddress.ip_address(target)
                return str(ip_obj)
            except ValueError:
                pass
                
            if not re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
                try:
                    return socket.gethostbyname(target)
                except socket.gaierror:
                    try:
                        answers = dns.resolver.resolve(target, 'A')
                        return answers[0].address
                    except:
                        return None
            return target
        except Exception as e:
            print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Resolution error: {e}{MatrixColors.Style.RESET}")
            return None
    
    def get_service_name(self, port, default="unknown"):
        service = PORT_SERVICES.get(port, default)
        if service == "unknown" and port in self.service_versions:
            return self.service_versions[port]
        return service
    
    def advanced_banner_grabbing(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((self.target_ip, port))
                
                if port == 80:
                    s.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % self.target.encode())
                elif port == 443:
                    s.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % self.target.encode())
                elif port == 21:
                    s.send(b"USER anonymous\r\n")
                elif port == 22:
                    s.send(b"SSH-2.0-OpenSSH_7.9\r\n")
                elif port == 25:
                    s.send(b"EHLO example.com\r\n")
                elif port == 3306:
                    s.send(b"\x0a")
                
                banner = s.recv(1024).decode(errors='ignore').strip()
                return self.clean_banner(banner)
        except Exception:
            return None
    
    def clean_banner(self, banner):
        if not banner:
            return None
            
        banner = re.sub(r'[\x00-\x1F\x7F-\xFF]', '', banner)
        return banner[:500] + "..." if len(banner) > 500 else banner
    
    def detect_service_version(self, port, banner):
        if not banner:
            return None
            
        version_patterns = {
            'SSH': r'SSH-([\d\.]+)',
            'HTTP': r'Server: ([^\r\n]+)',
            'FTP': r'220 ([^\r\n]+)',
            'SMTP': r'220 ([^\r\n]+)',
            'MySQL': r'([\d\.]+)-MySQL'
        }
        
        for service, pattern in version_patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                self.service_versions[port] = f"{service} {match.group(1)}"
                return match.group(1)
        return None
    
    def os_fingerprinting(self, open_ports):
        common_os = {
            (22, 80, 443): "Linux",
            (135, 139, 445): "Windows",
            (22, 3306, 8080): "Linux Server",
            (3389,): "Windows Server"
        }
        
        port_set = frozenset(port for port, _ in open_ports)
        for ports, os_name in common_os.items():
            if frozenset(ports).issubset(port_set):
                self.os_guesses.append(os_name)
        
        if not self.os_guesses:
            self.os_guesses.append("Unknown")
    
    def detect_waf(self):
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            try:
                response = requests.get(f"http://{self.target_ip}", headers=headers, timeout=self.timeout)
            except requests.exceptions.SSLError:
                response = requests.get(f"https://{self.target_ip}", headers=headers, timeout=self.timeout, verify=False)
            
            for waf_name, waf_data in WAF_FINGERPRINTS.items():
                for header in waf_data['headers']:
                    if header in response.headers:
                        for pattern in waf_data['patterns']:
                            if pattern in response.headers[header].lower():
                                self.waf_detected = waf_name
                                return waf_name
                
                for pattern in waf_data['patterns']:
                    if pattern in response.text.lower():
                        self.waf_detected = waf_name
                        return waf_name
                        
            return None
        except Exception:
            return None
    
    def device_fingerprinting(self, open_ports):
        open_port_list = [port for port, _, _ in open_ports]
        
        for device_type, fingerprint in DEVICE_FINGERPRINTS.items():
            port_match = all(port in open_port_list for port in fingerprint['ports'])
            if port_match:
                self.device_type = device_type
                return device_type
                
        return "Unknown"
    
    def geoip_lookup(self, ip_address):
        try:
            if not os.path.exists(CONFIG['geoip_db_path']):
                return None
                
            with geoip2.database.Reader(CONFIG['geoip_db_path']) as reader:
                response = reader.city(ip_address)
                geo_info = {
                    'country': response.country.name,
                    'city': response.city.name,
                    'postal': response.postal.code,
                    'latitude': response.location.latitude,
                    'longitude': response.location.longitude,
                    'timezone': response.location.time_zone
                }
                self.geo_info = geo_info
                return geo_info
        except Exception:
            return None
    
    def dns_analysis(self, domain):
        try:
            record_types = ['A', 'MX', 'NS', 'CNAME', 'TXT']
            results = {}
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    results[record_type] = [str(r) for r in answers]
                except:
                    pass
                    
            self.dns_records = results
            return results
        except Exception as e:
            print(f"{MatrixColors.Fore.BRIGHT_RED}[!] DNS analysis error: {e}{MatrixColors.Style.RESET}")
            return None
    
    def check_vulnerabilities(self, port, service, banner):
        for pattern, vuln_info in VULN_DB.items():
            if pattern.lower() in service.lower() or (banner and pattern.lower() in banner.lower()):
                self.vulnerabilities.append({
                    'port': port,
                    'service': service,
                    'vulnerability': vuln_info['CVE'],
                    'exploit': vuln_info['exploit']
                })
    
    def check_honeypot(self, port, banner):
        honeypot_indicators = [
            'honeypot', 'dionaea', 'kippo', 'cowrie', 'amun', 'glastopf'
        ]
        
        if banner:
            for indicator in honeypot_indicators:
                if indicator in banner.lower():
                    self.honeypot_indicators.append({
                        'port': port,
                        'indicator': indicator,
                        'type': 'Possible honeypot'
                    })
    
    def set_proxy(self, proxy_type, proxy_host, proxy_port):
        if proxy_type.lower() == 'socks5':
            socks.set_default_proxy(socks.SOCKS5, proxy_host, proxy_port)
            socket.socket = socks.socksocket
            self.proxy_config = {'type': 'SOCKS5', 'host': proxy_host, 'port': proxy_port}
        elif proxy_type.lower() == 'http':
            socks.set_default_proxy(socks.HTTP, proxy_host, proxy_port)
            socket.socket = socks.socksocket
            self.proxy_config = {'type': 'HTTP', 'host': proxy_host, 'port': proxy_port}
        else:
            print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Unsupported proxy type{MatrixColors.Style.RESET}")
    
    def scan_port(self, port):
        if not self.scanning:
            return
            
        try:
            with socket.socket(socket.AF_INET, NETWORK_PROTOCOLS[self.protocol]) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target_ip, port))
                
                if result == 0:
                    banner = None
                    service = self.get_service_name(port)
                    
                    if self.protocol == "tcp" and port in [21, 22, 25, 80, 110, 143, 443, 3306, 3389]:
                        banner = self.advanced_banner_grabbing(port)
                        if banner:
                            self.detect_service_version(port, banner)
                            self.check_vulnerabilities(port, service, banner)
                            self.check_honeypot(port, banner)
                    
                    with self.lock:
                        self.open_ports.append((port, service, banner))
                        
                        if not self.silent_mode:
                            status = f"{MatrixColors.Fore.BRIGHT_GREEN}open{MatrixColors.Style.RESET}"
                            banner_display = banner[:50] + "..." if banner and len(banner) > 50 else banner or "-"
                            print(f"[+] Port {port}/tcp {service.ljust(20)} {status.ljust(20)} {banner_display}")
        except Exception:
            pass
    
    def display_results(self):
        if not self.open_ports:
            print(f"{MatrixColors.Fore.BRIGHT_RED}[!] No open ports found{MatrixColors.Style.RESET}")
            return
            
        headers = ["Port", "Protocol", "Service", "Banner", "Status"]
        table_data = []
        
        for port, service, banner in sorted(self.open_ports, key=lambda x: x[0]):
            row = [
                port,
                self.protocol,
                service,
                banner[:100] + "..." if banner and len(banner) > 100 else banner or "-",
                f"{MatrixColors.Fore.BRIGHT_GREEN}open{MatrixColors.Style.RESET}"
            ]
            table_data.append(row)
            
        print(f"\n{MatrixColors.Fore.BRIGHT_CYAN}Scan Results:{MatrixColors.Style.RESET}")
        print(tabulate(table_data, headers=headers, tablefmt="grid"))
        
        if self.os_guesses:
            print(f"\n{MatrixColors.Fore.BRIGHT_YELLOW}Possible OS Detected:{MatrixColors.Style.RESET}")
            for os_guess in self.os_guesses:
                print(f"  - {os_guess}")
                
        if self.waf_detected:
            print(f"\n{MatrixColors.Fore.BRIGHT_YELLOW}WAF Detected:{MatrixColors.Style.RESET}")
            print(f"  - {self.waf_detected}")
            
        if self.device_type:
            print(f"\n{MatrixColors.Fore.BRIGHT_YELLOW}Device Type:{MatrixColors.Style.RESET}")
            print(f"  - {self.device_type}")
            
        if self.geo_info:
            print(f"\n{MatrixColors.Fore.BRIGHT_YELLOW}GeoIP Information:{MatrixColors.Style.RESET}")
            print(f"  - Country: {self.geo_info.get('country', 'Unknown')}")
            print(f"  - City: {self.geo_info.get('city', 'Unknown')}")
            print(f"  - Coordinates: {self.geo_info.get('latitude', '?')}, {self.geo_info.get('longitude', '?')}")
            
        if self.dns_records:
            print(f"\n{MatrixColors.Fore.BRIGHT_YELLOW}DNS Records:{MatrixColors.Style.RESET}")
            for record_type, values in self.dns_records.items():
                print(f"  - {record_type}: {', '.join(values)}")
                
        if self.vulnerabilities:
            print(f"\n{MatrixColors.Fore.BRIGHT_RED}Potential Vulnerabilities:{MatrixColors.Style.RESET}")
            for vuln in self.vulnerabilities:
                print(f"  - Port {vuln['port']}: {vuln['vulnerability']} ({vuln['exploit']})")
                
        if self.honeypot_indicators:
            print(f"\n{MatrixColors.Fore.BRIGHT_RED}Honeypot Indicators:{MatrixColors.Style.RESET}")
            for indicator in self.honeypot_indicators:
                print(f"  - Port {indicator['port']}: {indicator['type']} ({indicator['indicator']})")
    
    def run_scan(self, target, port_range=None, scan_type="normal", threads=200, silent=False):
        self.silent_mode = silent
        self.target = target
        self.target_ip = self.resolve_target(target)
        
        if not self.target_ip:
            print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Could not resolve target{MatrixColors.Style.RESET}")
            return False
            
        if port_range:
            try:
                start_port, end_port = map(int, port_range.split('-'))
                self.ports = range(start_port, end_port + 1)
            except ValueError:
                print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Invalid port range format. Use 'start-end'{MatrixColors.Style.RESET}")
                return False
        else:
            start_port, end_port = self.scan_types.get(scan_type, (1, 1024))
            self.ports = range(start_port, end_port + 1)
            
        self.threads = threads
        self.open_ports = []
        self.scanning = True
        self.service_versions = {}
        self.os_guesses = []
        self.scan_start_time = time.time()
        
        # Run additional scans
        self.detect_waf()
        self.dns_analysis(target)
        self.geoip_lookup(self.target_ip)
        
        if not self.silent_mode:
            print(f"\n{MatrixColors.Fore.BRIGHT_CYAN}[*] Starting scan on {target} ({self.target_ip}){MatrixColors.Style.RESET}")
            print(f"{MatrixColors.Fore.BRIGHT_CYAN}[*] Scanning ports: {self.ports[0]}-{self.ports[-1]} ({len(self.ports)} ports){MatrixColors.Style.RESET}")
            print(f"{MatrixColors.Fore.BRIGHT_CYAN}[*] Protocol: {self.protocol.upper()}{MatrixColors.Style.RESET}")
            print(f"{MatrixColors.Fore.BRIGHT_CYAN}[*] Using {threads} threads{MatrixColors.Style.RESET}")
            print(f"{MatrixColors.Fore.BRIGHT_YELLOW}[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{MatrixColors.Style.RESET}")
            print("-" * 70)
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            if not self.silent_mode:
                list(tqdm(executor.map(self.scan_port, self.ports), total=len(self.ports), desc="Scanning ports"))
            else:
                executor.map(self.scan_port, self.ports)
        
        self.scanning = False
        self.scan_end_time = time.time()
        scan_duration = self.scan_end_time - self.scan_start_time
        
        self.os_fingerprinting(self.open_ports)
        self.device_fingerprinting(self.open_ports)
        
        if not self.silent_mode:
            print("-" * 70)
            print(f"{MatrixColors.Fore.BRIGHT_YELLOW}[*] Scan completed in {scan_duration:.2f} seconds{MatrixColors.Style.RESET}")
            print(f"{MatrixColors.Fore.BRIGHT_GREEN}[+] Found {len(self.open_ports)} open ports{MatrixColors.Style.RESET}")
            self.display_results()
        
        return True
    
    def save_results(self, filename):
        if not self.open_ports:
            print(f"{MatrixColors.Fore.BRIGHT_RED}[!] No scan results to save{MatrixColors.Style.RESET}")
            return False
            
        try:
            if filename.endswith('.json'):
                data = {
                    'target': self.target,
                    'target_ip': self.target_ip,
                    'scan_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'duration': f"{self.scan_end_time - self.scan_start_time:.2f} seconds",
                    'protocol': self.protocol,
                    'os_guesses': self.os_guesses,
                    'waf': self.waf_detected,
                    'device_type': self.device_type,
                    'geo_info': self.geo_info,
                    'dns_records': self.dns_records,
                    'vulnerabilities': self.vulnerabilities,
                    'honeypot_indicators': self.honeypot_indicators,
                    'open_ports': [{
                        'port': port,
                        'protocol': self.protocol,
                        'service': service,
                        'banner': banner,
                        'status': 'open'
                    } for port, service, banner in sorted(self.open_ports, key=lambda x: x[0])]
                }
                with open(filename, 'w') as f:
                    json.dump(data, f, indent=4)
            elif filename.endswith('.html'):
                with open(filename, 'w') as f:
                    f.write(f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>iRC-PT Scan Results - {self.target}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
        .card {{ margin-bottom: 20px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }}
        .table-responsive {{ margin-bottom: 20px; }}
        .vulnerability {{ background-color: #fff3cd; }}
        .honeypot {{ background-color: #f8d7da; }}
        .port-open {{ background-color: #d1e7dd; }}
        h2 {{ color: #0d6efd; border-bottom: 2px solid #0d6efd; padding-bottom: 5px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="row mt-4">
            <div class="col-12">
                <div class="card">
                    <div class="card-header bg-primary text-white">
                        <h1 class="h4">iRC-PT Matrix Scanner v9.0 Pro - Scan Report</h1>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <p><strong>Target:</strong> {self.target} ({self.target_ip})</p>
                                <p><strong>Scan time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                                <p><strong>Duration:</strong> {self.scan_end_time - self.scan_start_time:.2f} seconds</p>
                            </div>
                            <div class="col-md-6">
                                <p><strong>Protocol:</strong> {self.protocol.upper()}</p>
                                <p><strong>Open ports:</strong> {len(self.open_ports)}</p>
                                <p><strong>WAF detected:</strong> {self.waf_detected or 'None'}</p>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header bg-info text-white">
                        <h2 class="h5">Open Ports</h2>
                    </div>
                    <div class="card-body">
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th>Port</th>
                                        <th>Protocol</th>
                                        <th>Service</th>
                                        <th>Banner</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody>
                    """)
                    
                    for port, service, banner in sorted(self.open_ports, key=lambda x: x[0]):
                        f.write(f"""
                                    <tr class="port-open">
                                        <td>{port}</td>
                                        <td>{self.protocol}</td>
                                        <td>{service}</td>
                                        <td><small>{banner or '-'}</small></td>
                                        <td><span class="badge bg-success">open</span></td>
                                    </tr>
                        """)
                    
                    f.write("""
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header bg-warning text-dark">
                        <h2 class="h5">System Information</h2>
                    </div>
                    <div class="card-body">
                        <div class="row">
                            <div class="col-md-6">
                                <h3 class="h6">Operating System</h3>
                                <ul>
                    """)
                    
                    for os_guess in self.os_guesses:
                        f.write(f"""
                                    <li>{os_guess}</li>
                        """)
                    
                    f.write(f"""
                                </ul>
                                <h3 class="h6">Device Type</h3>
                                <p>{self.device_type or 'Unknown'}</p>
                            </div>
                            <div class="col-md-6">
                                <h3 class="h6">GeoIP Information</h3>
                                <ul>
                                    <li>Country: {self.geo_info.get('country', 'Unknown') if self.geo_info else 'Unknown'}</li>
                                    <li>City: {self.geo_info.get('city', 'Unknown') if self.geo_info else 'Unknown'}</li>
                                    <li>Coordinates: {self.geo_info.get('latitude', '?') if self.geo_info else '?'}, {self.geo_info.get('longitude', '?') if self.geo_info else '?'}</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header bg-danger text-white">
                        <h2 class="h5">Security Findings</h2>
                    </div>
                    <div class="card-body">
                    """)
                    
                    if self.vulnerabilities:
                        f.write("""
                        <h3 class="h6">Vulnerabilities</h3>
                        <div class="table-responsive">
                            <table class="table table-bordered vulnerability">
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>Service</th>
                                        <th>CVE</th>
                                        <th>Exploit</th>
                                    </tr>
                                </thead>
                                <tbody>
                        """)
                        
                        for vuln in self.vulnerabilities:
                            f.write(f"""
                                    <tr>
                                        <td>{vuln['port']}</td>
                                        <td>{vuln['service']}</td>
                                        <td>{vuln['vulnerability']}</td>
                                        <td>{vuln['exploit']}</td>
                                    </tr>
                            """)
                        
                        f.write("""
                                </tbody>
                            </table>
                        </div>
                        """)
                    
                    if self.honeypot_indicators:
                        f.write("""
                        <h3 class="h6 mt-4">Honeypot Indicators</h3>
                        <div class="table-responsive">
                            <table class="table table-bordered honeypot">
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>Type</th>
                                        <th>Indicator</th>
                                    </tr>
                                </thead>
                                <tbody>
                        """)
                        
                        for indicator in self.honeypot_indicators:
                            f.write(f"""
                                    <tr>
                                        <td>{indicator['port']}</td>
                                        <td>{indicator['type']}</td>
                                        <td>{indicator['indicator']}</td>
                                    </tr>
                            """)
                        
                        f.write("""
                                </tbody>
                            </table>
                        </div>
                        """)
                    
                    f.write("""
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header bg-secondary text-white">
                        <h2 class="h5">DNS Information</h2>
                    </div>
                    <div class="card-body">
                        <div class="row">
                    """)
                    
                    for record_type, values in self.dns_records.items():
                        f.write(f"""
                            <div class="col-md-6">
                                <h3 class="h6">{record_type} Records</h3>
                                <ul>
                        """)
                        for value in values:
                            f.write(f"""
                                    <li>{value}</li>
                            """)
                        f.write("""
                                </ul>
                            </div>
                        """)
                    
                    f.write("""
                        </div>
                    </div>
                </div>
                
                <div class="card mt-4">
                    <div class="card-header bg-dark text-white">
                        <h2 class="h5">Recommendations</h2>
                    </div>
                    <div class="card-body">
                        <ul>
                            <li>Close all unnecessary open ports</li>
                            <li>Update services to their latest versions</li>
                            <li>Implement proper firewall rules</li>
                            <li>Monitor for suspicious activities</li>
                        </ul>
                    </div>
                </div>
                
                <div class="text-center mt-4 mb-4">
                    <p class="text-muted">Report generated by iRC-PT Matrix Scanner v9.0 Pro</p>
                </div>
            </div>
        </div>
    </div>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
                    """)
            elif filename.endswith('.xml'):
                root = ET.Element("scan_results")
                ET.SubElement(root, "target").text = self.target
                ET.SubElement(root, "target_ip").text = self.target_ip
                ET.SubElement(root, "scan_time").text = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                ET.SubElement(root, "duration").text = f"{self.scan_end_time - self.scan_start_time:.2f} seconds"
                ET.SubElement(root, "protocol").text = self.protocol
                
                os_guesses = ET.SubElement(root, "os_guesses")
                for guess in self.os_guesses:
                    ET.SubElement(os_guesses, "os").text = guess
                
                ports = ET.SubElement(root, "open_ports")
                for port, service, banner in sorted(self.open_ports, key=lambda x: x[0]):
                    port_elem = ET.SubElement(ports, "port")
                    ET.SubElement(port_elem, "number").text = str(port)
                    ET.SubElement(port_elem, "protocol").text = self.protocol
                    ET.SubElement(port_elem, "service").text = service
                    ET.SubElement(port_elem, "banner").text = banner or ""
                    ET.SubElement(port_elem, "status").text = "open"
                
                tree = ET.ElementTree(root)
                tree.write(filename, encoding='utf-8', xml_declaration=True)
            elif filename.endswith('.csv'):
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Port", "Protocol", "Service", "Banner", "Status"])
                    for port, service, banner in sorted(self.open_ports, key=lambda x: x[0]):
                        writer.writerow([port, self.protocol, service, banner or "", "open"])
            else:  
                with open(filename, 'w') as f:
                    f.write(f"iRC-PT Matrix Scanner v9.0 Pro - Scan Results\n")
                    f.write(f"Target: {self.target} ({self.target_ip})\n")
                    f.write(f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Duration: {self.scan_end_time - self.scan_start_time:.2f} seconds\n")
                    f.write(f"Protocol: {self.protocol.upper()}\n")
                    f.write(f"WAF detected: {self.waf_detected or 'None'}\n")
                    f.write(f"Device type: {self.device_type or 'Unknown'}\n\n")
                    
                    f.write(f"Open ports:\n")
                    for port, service, banner in sorted(self.open_ports, key=lambda x: x[0]):
                        f.write(f"{port}/{self.protocol} {service}")
                        if banner:
                            f.write(f" - Banner: {banner}\n")
                        else:
                            f.write("\n")
                    
                    if self.os_guesses:
                        f.write("\nPossible Operating System:\n")
                        for os_guess in self.os_guesses:
                            f.write(f"- {os_guess}\n")
                    
                    if self.vulnerabilities:
                        f.write("\nPotential Vulnerabilities:\n")
                        for vuln in self.vulnerabilities:
                            f.write(f"- Port {vuln['port']}: {vuln['vulnerability']} ({vuln['exploit']})\n")
                    
                    if self.honeypot_indicators:
                        f.write("\nHoneypot Indicators:\n")
                        for indicator in self.honeypot_indicators:
                            f.write(f"- Port {indicator['port']}: {indicator['type']} ({indicator['indicator']})\n")
            
            print(f"{MatrixColors.Fore.BRIGHT_GREEN}[+] Results saved to {filename}{MatrixColors.Style.RESET}")
            return True
        except Exception as e:
            print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Error saving file: {e}{MatrixColors.Style.RESET}")
            return False
    
    def generate_pdf_report(self, filename):
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", 'B', 16)
            pdf.cell(0, 10, f"iRC-PT Matrix Scanner v9.0 Pro - Scan Report", 0, 1, 'C')
            
            pdf.set_font("Arial", '', 12)
            pdf.cell(0, 10, f"Target: {self.target} ({self.target_ip})", 0, 1)
            pdf.cell(0, 10, f"Scan time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
            pdf.cell(0, 10, f"Duration: {self.scan_end_time - self.scan_start_time:.2f} seconds", 0, 1)
            pdf.cell(0, 10, f"Protocol: {self.protocol.upper()}", 0, 1)
            pdf.cell(0, 10, f"WAF detected: {self.waf_detected or 'None'}", 0, 1)
            pdf.cell(0, 10, f"Device type: {self.device_type or 'Unknown'}", 0, 1)
            
            pdf.ln(10)
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, "Open Ports", 0, 1)
            
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(30, 10, "Port", 1)
            pdf.cell(30, 10, "Protocol", 1)
            pdf.cell(50, 10, "Service", 1)
            pdf.cell(80, 10, "Banner", 1)
            pdf.ln()
            
            pdf.set_font("Arial", '', 10)
            for port, service, banner in sorted(self.open_ports, key=lambda x: x[0]):
                pdf.cell(30, 10, str(port), 1)
                pdf.cell(30, 10, self.protocol, 1)
                pdf.cell(50, 10, service, 1)
                pdf.cell(80, 10, banner[:60] + "..." if banner and len(banner) > 60 else banner or "-", 1)
                pdf.ln()
            
            if self.os_guesses:
                pdf.ln(10)
                pdf.set_font("Arial", 'B', 14)
                pdf.cell(0, 10, "Operating System Detection", 0, 1)
                pdf.set_font("Arial", '', 12)
                for os_guess in self.os_guesses:
                    pdf.cell(0, 10, f"- {os_guess}", 0, 1)
            
            if self.vulnerabilities:
                pdf.ln(10)
                pdf.set_font("Arial", 'B', 14)
                pdf.cell(0, 10, "Vulnerabilities", 0, 1)
                
                pdf.set_font("Arial", 'B', 12)
                pdf.cell(20, 10, "Port", 1)
                pdf.cell(40, 10, "Service", 1)
                pdf.cell(50, 10, "CVE", 1)
                pdf.cell(80, 10, "Exploit", 1)
                pdf.ln()
                
                pdf.set_font("Arial", '', 10)
                for vuln in self.vulnerabilities:
                    pdf.cell(20, 10, str(vuln['port']), 1)
                    pdf.cell(40, 10, vuln['service'], 1)
                    pdf.cell(50, 10, vuln['vulnerability'], 1)
                    pdf.cell(80, 10, vuln['exploit'], 1)
                    pdf.ln()
            
            pdf.output(filename)
            print(f"{MatrixColors.Fore.BRIGHT_GREEN}[+] PDF report saved to {filename}{MatrixColors.Style.RESET}")
            return True
        except Exception as e:
            print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Error generating PDF: {e}{MatrixColors.Style.RESET}")
            return False
    
    def schedule_scan(self, target, interval_hours, output_file=None):
        def scan_job():
            while True:
                print(f"\n{MatrixColors.Fore.BRIGHT_CYAN}[*] Running scheduled scan on {target}{MatrixColors.Style.RESET}")
                self.run_scan(target)
                if output_file:
                    self.save_results(output_file)
                time.sleep(interval_hours * 3600)
        
        job_thread = Thread(target=scan_job)
        job_thread.daemon = True
        job_thread.start()
        CONFIG['scheduled_scans'][target] = job_thread
        print(f"{MatrixColors.Fore.BRIGHT_GREEN}[+] Scheduled scan started for {target} every {interval_hours} hours{MatrixColors.Style.RESET}")
    
    def show_help(self):
        print(f"""
{MatrixColors.Fore.BRIGHT_CYAN}iRC-PT Matrix Scanner v9.0 Pro Commands:{MatrixColors.Style.RESET}
{MatrixColors.Fore.BRIGHT_GREEN}scan <target> [port-range|scan-type] [threads]{MatrixColors.Style.RESET} - Start a port scan
    Examples:
      scan example.com 1-1000 200
      scan example.com quick
      scan example.com full 500
    
{MatrixColors.Fore.BRIGHT_GREEN}services{MatrixColors.Style.RESET} - Show common port services
    
{MatrixColors.Fore.BRIGHT_GREEN}save <filename>{MatrixColors.Style.RESET} - Save scan results to file
    Supported formats: .txt, .json, .html, .xml, .csv
    Example: save results.json
    
{MatrixColors.Fore.BRIGHT_GREEN}report <filename.pdf>{MatrixColors.Style.RESET} - Generate PDF security report
    
{MatrixColors.Fore.BRIGHT_GREEN}proxy <type> <host> <port>{MatrixColors.Style.RESET} - Set proxy (socks5/http)
    Example: proxy socks5 127.0.0.1 9050
    
{MatrixColors.Fore.BRIGHT_GREEN}schedule <target> <hours> [output]{MatrixColors.Style.RESET} - Schedule recurring scans
    Example: schedule example.com 24 results.json
    
{MatrixColors.Fore.BRIGHT_GREEN}clear{MatrixColors.Style.RESET} - Clear the screen
    
{MatrixColors.Fore.BRIGHT_GREEN}history{MatrixColors.Style.RESET} - Show command history
    
{MatrixColors.Fore.BRIGHT_GREEN}exit{MatrixColors.Style.RESET} - Exit the scanner
    
{MatrixColors.Fore.BRIGHT_GREEN}help{MatrixColors.Style.RESET} - Show this help message
        """)
    
    def show_services(self):
        print(f"\n{MatrixColors.Fore.BRIGHT_CYAN}Common Port Services:{MatrixColors.Style.RESET}")
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 5900]
        table_data = []
        for port in common_ports:
            service = self.get_service_name(port)
            table_data.append([port, "tcp", service])
            
        print(tabulate(table_data, headers=["Port", "Protocol", "Service"], tablefmt="grid"))
    
    def show_history(self):
        if not self.command_history:
            print(f"{MatrixColors.Fore.BRIGHT_YELLOW}[*] No commands in history{MatrixColors.Style.RESET}")
            return
            
        print(f"\n{MatrixColors.Fore.BRIGHT_CYAN}Command History:{MatrixColors.Style.RESET}")
        for i, cmd in enumerate(self.command_history, 1):
            print(f"  {i}. {cmd}")
    
    def handle_command(self, command):
        self.command_history.append(command)
        parts = command.split()
        
        if not parts:
            return
            
        cmd = parts[0].lower()
        
        if cmd == "scan" and len(parts) >= 2:
            threads = 200
            port_range = None
            scan_type = "normal"
            
            if len(parts) >= 3:
                if '-' in parts[2]:
                    port_range = parts[2]
                elif parts[2] in self.scan_types:
                    scan_type = parts[2]
                
                if len(parts) >= 4:
                    try:
                        threads = int(parts[3])
                    except ValueError:
                        print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Invalid thread count{MatrixColors.Style.RESET}")
                        return
            
            if os.path.isfile(parts[1]):
                with open(parts[1], 'r') as f:
                    targets = [line.strip() for line in f if line.strip()]
                for target in targets:
                    print(f"\n{MatrixColors.Fore.BRIGHT_CYAN}[*] Scanning target: {target}{MatrixColors.Style.RESET}")
                    self.run_scan(target, port_range, scan_type, threads)
            else:
                self.run_scan(parts[1], port_range, scan_type, threads)
            
        elif cmd == "services":
            self.show_services()
            
        elif cmd == "save" and len(parts) >= 2:
            self.save_results(parts[1])
            
        elif cmd == "report" and len(parts) >= 2:
            self.generate_pdf_report(parts[1])
            
        elif cmd == "proxy" and len(parts) >= 4:
            self.set_proxy(parts[1], parts[2], int(parts[3]))
            print(f"{MatrixColors.Fore.BRIGHT_GREEN}[+] Proxy set to {parts[1]}://{parts[2]}:{parts[3]}{MatrixColors.Style.RESET}")
            
        elif cmd == "schedule" and len(parts) >= 3:
            output = parts[3] if len(parts) >= 4 else None
            try:
                interval = int(parts[2])
                self.schedule_scan(parts[1], interval, output)
            except ValueError:
                print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Invalid interval{MatrixColors.Style.RESET}")
            
        elif cmd == "clear":
            os.system('clear' if os.name == 'posix' else 'cls')
            show_matrix_banner()
            
        elif cmd == "history":
            self.show_history()
            
        elif cmd == "exit":
            print(f"{MatrixColors.Fore.BRIGHT_RED}Exiting iRC-PT Matrix Scanner...{MatrixColors.Style.RESET}")
            sys.exit(0)
            
        elif cmd == "help":
            self.show_help()
            
        else:
            print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Unknown command. Type 'help' for available commands.{MatrixColors.Style.RESET}")
    
    def start_interactive(self):
        show_matrix_banner()
        print(f"{MatrixColors.Fore.BRIGHT_GREEN}Type 'help' for available commands{MatrixColors.Style.RESET}\n")
        
        while True:
            try:
                prompt = f"{MatrixColors.Fore.BRIGHT_RED}iRC-PT{MatrixColors.Fore.BRIGHT_WHITE}@{MatrixColors.Fore.BRIGHT_GREEN}scanner{MatrixColors.Style.RESET}> "
                command = input(prompt).strip()
                if command:
                    self.handle_command(command)
            except KeyboardInterrupt:
                print("\nUse 'exit' to quit")
            except EOFError:
                print("\nUse 'exit' to quit")

def parse_args():
    parser = argparse.ArgumentParser(description='iRC-PT Matrix Scanner v9.0 Pro - Advanced Network Security Analyzer')
    parser.add_argument('command', nargs='?', help='Command to execute (scan)')
    parser.add_argument('target', nargs='?', help='Target IP/domain or file with targets')
    parser.add_argument('port_range_or_type', nargs='?', default='normal', help='Port range (1-1000) or scan type (quick/normal/full)')
    parser.add_argument('--threads', type=int, default=200, help='Number of threads to use')
    parser.add_argument('--silent', action='store_true', help='Silent mode (no output)')
    parser.add_argument('--output', help='Output file to save results')
    parser.add_argument('--protocol', choices=['tcp', 'udp'], default='tcp', help='Protocol to scan (tcp/udp)')
    parser.add_argument('--proxy', help='Proxy configuration (type:host:port)')
    parser.add_argument('--api', action='store_true', help='Start in API mode')
    return parser.parse_args()

def run_api_server(scanner):
    @api_app.route('/api/scan', methods=['POST'])
    def api_scan():
        data = request.json
        if not data or 'target' not in data:
            return jsonify({'error': 'Missing target'}), 400
        
        target = data['target']
        port_range = data.get('port_range')
        scan_type = data.get('scan_type', 'normal')
        threads = data.get('threads', 200)
        protocol = data.get('protocol', 'tcp')
        
        scanner.protocol = protocol
        success = scanner.run_scan(target, port_range, scan_type, threads, silent=True)
        
        if not success:
            return jsonify({'error': 'Scan failed'}), 500
        
        return jsonify({
            'target': scanner.target,
            'target_ip': scanner.target_ip,
            'open_ports': [{
                'port': port,
                'service': service,
                'banner': banner
            } for port, service, banner in scanner.open_ports],
            'os_guesses': scanner.os_guesses,
            'waf': scanner.waf_detected,
            'device_type': scanner.device_type
        })
    
    @api_app.route('/api/stop', methods=['POST'])
    def api_stop():
        scanner.scanning = False
        return jsonify({'status': 'scan stopped'})
    
    print(f"{MatrixColors.Fore.BRIGHT_CYAN}[*] Starting API server on port 5000{MatrixColors.Style.RESET}")
    api_app.run(host='0.0.0.0', port=5000)

def main():
    args = parse_args()
    scanner = IRCPTScanner()
    scanner.protocol = args.protocol.lower()
    
    if args.proxy:
        try:
            proxy_type, proxy_host, proxy_port = args.proxy.split(':')
            scanner.set_proxy(proxy_type, proxy_host, int(proxy_port))
            print(f"{MatrixColors.Fore.BRIGHT_GREEN}[+] Proxy set to {proxy_type}://{proxy_host}:{proxy_port}{MatrixColors.Style.RESET}")
        except ValueError:
            print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Invalid proxy format. Use type:host:port{MatrixColors.Style.RESET}")
    
    if args.api:
        global api_mode
        api_mode = True
        run_api_server(scanner)
    elif args.command == 'scan' and args.target:
        if os.path.isfile(args.target):
            with open(args.target, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
            for target in targets:
                scanner.run_scan(target, args.port_range_or_type if '-' in args.port_range_or_type else None,
                               args.port_range_or_type if args.port_range_or_type in scanner.scan_types else 'normal',
                               args.threads, args.silent)
                if args.output:
                    base, ext = os.path.splitext(args.output)
                    filename = f"{base}_{target}{ext}"
                    scanner.save_results(filename)
        else:
            scanner.run_scan(args.target, args.port_range_or_type if '-' in args.port_range_or_type else None,
                           args.port_range_or_type if args.port_range_or_type in scanner.scan_types else 'normal',
                           args.threads, args.silent)
            if args.output:
                scanner.save_results(args.output)
    elif args.command:
        print(f"{MatrixColors.Fore.BRIGHT_RED}[!] Invalid command or arguments{MatrixColors.Style.RESET}")
        print(f"Usage: {sys.argv[0]} scan <target> [port-range|scan-type] [--threads N] [--silent] [--output file] [--protocol tcp|udp] [--proxy type:host:port] [--api]")
    else:
        scanner.start_interactive()

if __name__ == "__main__":
    main()
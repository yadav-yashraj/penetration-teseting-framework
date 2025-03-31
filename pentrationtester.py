  1 import os$
  2 import socket$
  3 import subprocess$
  4 import nmap$
  5 $
  6 class PenetrationTestingFramework:$
  7     def __init__(self):$
  8         self.nm = nmap.PortScanner()$
  9 $
 10     def reconnaissance(self, target):$
 11         print(f"[+] Performing Reconnaissance on {target}")$
 12         try:$
 13             ip = socket.gethostbyname(target)$
 14             print(f"[*] IP Address: {ip}")$
 15         except socket.gaierror:$
 16             print("[-] Could not resolve host")$
 17 $
 18     def scan_ports(self, target):$
 19         print(f"[+] Scanning ports on {target}")$
 20         self.nm.scan(target, '1-65535', '-sV')$
 21         for host in self.nm.all_hosts():$
 22             for proto in self.nm[host].all_protocols():$
 23                 ports = self.nm[host][proto].keys()$
 24                 for port in ports:$
 25                     state = self.nm[host][proto][port]['state']$
 26                     service = self.nm[host][proto][port]['name']$
 27                     print(f"[*] Port {port}: {service} ({state})")$
 28 $
 29     def exploit(self, target, exploit_name):$
 30         print(f"[+] Attempting Exploit: {exploit_name} on {target}")$
 31         # Example placeholder for exploit execution$
 32         if exploit_name == "smbghost":$
 33             print("[*] Running SMBGhost exploit...")$
 34             os.system(f"python3 smbghost_exploit.py {target}")$
 35         else:$
 36             print("[-] Exploit not found")$
 37 $
 38     def generate_report(self, target, findings):$
 39         with open("pentest_report.txt", "w") as report:$
 40             report.write(f"Pentest Report for {target}\n")$
 41             report.write("="*50 + "\n")$
 42             for finding in findings:$
 43                 report.write(finding + "\n")$
 44         print("[+] Report generated: pentest_report.txt")$
 45 $
 46 if __name__ == "__main__":$
 47     framework = PenetrationTestingFramework()$
 48     target = input("Enter Target Domain/IP: ")$
 49     framework.reconnaissance(target)$
 50     framework.scan_ports(target)$
 51     exploit_choice = input("Enter Exploit Name (or skip): ")$
 52     if exploit_choice:$
 53         framework.exploit(target, exploit_choice)$
 54     framework.generate_report(target, ["Example finding: Open port 80 running Apache"])$
 55 i$
~
~
~
~
~
~
~
~
penetrationtester.py [+]                                                                                                                                                                                                                                                                                                                                                   55,2           All
-- INSERT --                                                                                                                                                                                                                                                                                                                                                                        

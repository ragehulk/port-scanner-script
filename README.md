# port-scanner-script


The code of the script.

```
import socket
import threading
from queue import Queue

target = input("Enter the target IP address: ")
open_ports = []
filtered_ports = []
closed_port_count = 0

# Port-Service mappings
port_services = {
    7: "Echo",
    20: "FTP - Data",
    21: "FTP - Control",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    42: "WINS Replication",
    43: "WHOIS",
    49: "TACACS",
    53: "DNS",
    67: "DHCP - Server",
    68: "DHCP - Client",
    69: "TFTP",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTP - SSL",
    514: "Syslog",
    520: "RIP",
    546: "DHCPv6 - Server",
    547: "DHCPv6 - Client",
    563: "NNTP - SSL",
    631: "IPP",
    636: "LDAP - SSL",
    873: "RSYNC",
    989: "FTP - SSL (Control)",
    990: "FTP - SSL (Data)",
    993: "IMAP - SSL",
    995: "POP3 - SSL",
    1433: "MS SQL",
    1434: "MS SQL - Monitor",
    1521: "Oracle SQL",
    1701: "L2TP",
    1723: "PPTP",
    2082: "cPanel",
    2083: "cPanel - SSL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    5901: "VNC - Screen 1",
    5902: "VNC - Screen 2",
    6379: "Redis",
    8080: "HTTP Proxy",
    8443: "HTTPS Proxy"
    # You can add other port-service mappings here
}

def get_service(port):
    if port in port_services:
        return port_services[port]
    else:
        return "Unknown Service"

def port_scan(port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            open_ports.append(port)
            service = get_service(port)
            print(f"Port {port} is open - Protocol: {socket.getservbyport(port)} - Service: {service}")
        elif result == 113:
            filtered_ports.append(port)
            print(f"Port {port} is filtered")
        else:
            global closed_port_count
            closed_port_count += 1
        sock.close()
    except KeyboardInterrupt:
        print("\nScan canceled by the user.")
        exit()
    except socket.gaierror:
        print("Invalid target address. Please enter a valid IP address.")
        exit()
    except socket.error:
        print("Connection error.")
        exit()

def worker():
    while not q.empty():
        port = q.get()
        port_scan(port)
        q.task_done()

q = Queue()

for x in range(1000):
    q.put(x)

for _ in range(30):  # You can use any number of threads you want
    t = threading.Thread(target=worker)
    t.start()

q.join()

print("\nScan completed.")

print(f"\nOpen ports: {open_ports}")
print(f"Filtered ports: {filtered_ports}")
print(f"Closed port count: {closed_port_count}")

```


1. Make sure you have access to a computer or virtual machine running Kali Linux operating system.
2. Ensure that Python 3 is installed. Kali Linux usually comes with Python 3 pre-installed. If it's not installed, you can install Python 3 using the following commands:
   ```
   sudo apt update
   sudo apt install python3
   ```
3. Use a text editor (such as nano or vim) to paste the code into a Python file and save it. For example, you can create a file named `port_scanner.py`:
   ```
   nano port_scanner.py
   ```
4. Then, open a terminal and run the Python file:
   ```
   python3 port_scanner.py
   ```
5. When the program is executed, you will be prompted to enter the target IP address. Enter the desired IP address and press Enter.
6. The code will perform a SYN scan on the specified target IP address and display the open ports, their protocols, and services.

WARNING: The script only scans the first 1000 ports. If you want to scan more ports, you can modify the range section.

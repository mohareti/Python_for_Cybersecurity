import socket
import ipaddress
import concurrent.futures
import subprocess
import platform
#mohareti
def ping(ip):
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    command = ['ping', param, '1', str(ip)]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0

def scan_ip(ip):
    try:
        if ping(ip):
            try:
                hostname = socket.gethostbyaddr(str(ip))[0]
                return (str(ip), hostname)
            except socket.herror:
                pass
    except:
        pass
    return None

def scan_network():
    # Get your IP address and subnet
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    network = ipaddress.IPv4Network(f'{ip}/24', strict=False)
    print(f"Scanning network: {network}")
    
    devices = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(scan_ip, network.hosts())
        devices = [device for device in results if device is not None]
    
    return devices

if __name__ == "__main__":
    devices = scan_network()
    
    if devices:
        print("\nDevices found with hostnames:")
        print("-----------------------------")
        for ip, hostname in devices:
            print(f"IP: {ip:<15} Hostname: {hostname}")
    else:
        print("No devices found with available hostnames.")

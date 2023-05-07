import argparse
import socket
import requests

def scan_ports(target, ports):
    print(f"Scanning ports for {target}...")
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open")
        sock.close()

def scan_services(target, ports):
    print(f"Scanning services for {target}...")
    for port in ports:
        try:
            service = socket.getservbyport(port)
            print(f"Port {port} ({service}) is open")
        except:
            print(f"Port {port} is open, but service is unknown")

def test_vulnerabilities(url):
    print(f"Testing web vulnerabilities for {url}...")
    # Perform vulnerability tests here
    # Example: test for SQL injection
    payload = "' OR '1'='1"
    response = requests.get(url + "/search?keyword=" + payload)
    if payload in response.text:
        print("Website is vulnerable to SQL injection")
# main function
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Website Penetration Testing Tool")
    parser.add_argument("target", help="Target website URL or IP address")
    parser.add_argument("-p", "--ports", nargs="+", type=int, default=[80, 443],
                        help="List of ports to scan (default: 80, 443)")
    parser.add_argument("-s", "--services", action="store_true",
                        help="Scan and identify open services")
    parser.add_argument("-v", "--vulnerabilities", action="store_true",
                        help="Test for common web vulnerabilities")

    args = parser.parse_args()

    target = args.target
    ports = args.ports

    if args.services:
        scan_services(target, ports)

    if args.vulnerabilities:
        test_vulnerabilities(target)

    if not args.services and not args.vulnerabilities:
        scan_ports(target, ports)
import socket
import pyfiglet
import os
from datetime import datetime
from colorama import Fore, init
import threading
import subprocess
import requests

# Inisialisasi Colorama
init(autoreset=True)

VERSION = "v1.0"

def banner():
    ascii_banner = pyfiglet.figlet_format("Scanner Tools")
    print(Fore.CYAN + ascii_banner)
    print(Fore.YELLOW + "=" * 60)
    print(Fore.MAGENTA + "🔧 Coded by Hotaa404 🔧")
    print(Fore.GREEN + f"🛠️  Scanning Tool ({VERSION}) 🛠️")
    print(Fore.YELLOW + "=" * 60)
    print(Fore.LIGHTBLUE_EX + f"✨ Start Time: {datetime.now()} ✨\n")

def display_menu():
    print(Fore.YELLOW + "=" * 60)
    print(Fore.MAGENTA + "[1] Scan Ports")
    print(Fore.MAGENTA + "[2] Check Service Version")
    print(Fore.MAGENTA + "[3] Ping Target")
    print(Fore.MAGENTA + "[4] Scan Specific Port")
    print(Fore.MAGENTA + "[5] Get Banner from Port")
    print(Fore.MAGENTA + "[6] Network Information")
    print(Fore.MAGENTA + "[7] Whois Lookup")
    print(Fore.MAGENTA + "[8] Traceroute")
    print(Fore.MAGENTA + "[9] Export Result")
    print(Fore.MAGENTA + "[10] Search for CVE Vulnerabilities")
    print(Fore.MAGENTA + "[11] OS Detection")
    print(Fore.MAGENTA + "[12] Exit")
    print(Fore.YELLOW + "=" * 60)

def cve_search():
    service_version = input(Fore.CYAN + "[?] Enter service version (e.g., Apache 2.4.46): ")
    try:
        response = requests.get(f"https://cve.circl.lu/api/cve?cveid={service_version}")
        if response.status_code == 200:
            cve_data = response.json()
            if cve_data:
                print(Fore.GREEN + f"CVE Results for {service_version}:")
                for item in cve_data['result']:
                    print(Fore.LIGHTYELLOW_EX + f"CVE-ID: {item['CVE']} - Description: {item['description']}")
            else:
                print(Fore.RED + f"No CVE found for version {service_version}.")
        else:
            print(Fore.RED + "⚠️ Unable to retrieve CVE data.")
    except Exception as e:
        print(Fore.RED + f"⚠️ Error performing CVE search: {str(e)}")

def vuln_database_lookup():
    port = int(input(Fore.CYAN + "[?] Enter port number for vulnerability lookup: "))
    vuln_references = {
        21: "FTP vulnerabilities",
        22: "SSH vulnerabilities",
        23: "Telnet vulnerabilities",
        25: "SMTP vulnerabilities",
        80: "HTTP vulnerabilities (e.g., Apache, Nginx)",
        443: "HTTPS vulnerabilities",
        3306: "MySQL vulnerabilities",
        8080: "HTTP Proxy vulnerabilities",
    }
    try:
        if port in vuln_references:
            print(Fore.GREEN + f"Vulnerabilities for port {port}: {vuln_references[port]}")
        else:
            print(Fore.RED + f"No known vulnerabilities for port {port}.")
    except Exception as e:
        print(Fore.RED + f"⚠️ Error during vulnerability lookup: {str(e)}")

def os_detection():
    host = input(Fore.CYAN + "[?] Enter IP or Hostname for OS detection: ")
    try:
        # This is a basic OS detection by analyzing open ports and banners
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((host, 80))  # Checking for HTTP port 80
        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = sock.recv(1024).decode().strip()
        sock.close()

        if "Linux" in banner:
            print(Fore.GREEN + f"OS Detected: Linux-based system detected on {host}.")
        elif "Windows" in banner:
            print(Fore.GREEN + f"OS Detected: Windows-based system detected on {host}.")
        else:
            print(Fore.RED + f"OS Detection: Unknown OS for {host}.")
    except Exception as e:
        print(Fore.RED + f"⚠️ Error detecting OS: {str(e)}")

def main():
    try:
        banner()
        while True:
            display_menu()
            choice = input(Fore.CYAN + "[?] Please select an option: ")

            if choice == '1':
                host = input(Fore.CYAN + "[?] Enter IP or Hostname: ")
                start_port = int(input(Fore.CYAN + "[?] Enter starting port: "))
                end_port = int(input(Fore.CYAN + "[?] Enter ending port: "))
                print(Fore.MAGENTA + "\n🚀 Scanning started...\n")
                start_time = datetime.now()
                scan_ports(host, start_port, end_port)
                show_summary(start_time)

            elif choice == '2':
                host = input(Fore.CYAN + "[?] Enter IP or Hostname: ")
                start_port = int(input(Fore.CYAN + "[?] Enter starting port: "))
                end_port = int(input(Fore.CYAN + "[?] Enter ending port: "))
                print(Fore.MAGENTA + "\n🚀 Checking service versions...\n")
                check_service_version(host, start_port, end_port)

            elif choice == '3':
                ping_target()

            elif choice == '4':
                scan_specific_port()

            elif choice == '5':
                get_banner()

            elif choice == '6':
                network_information()

            elif choice == '7':
                whois_lookup()

            elif choice == '8':
                traceroute()

            elif choice == '9':
                result = input(Fore.CYAN + "[?] Enter data to export: ")
                export_result(result)

            elif choice == '10':
                cve_search()

            elif choice == '11':
                os_detection()

            elif choice == '12':
                print(Fore.LIGHTGREEN_EX + "🚀 Exiting... Goodbye!")
                break

            else:
                print(Fore.RED + "⚠️ Invalid choice, please try again.")

    except ValueError:
        print(Fore.RED + "⚠️ Invalid input!")
    except KeyboardInterrupt:
        print(Fore.RED + "\n⚠️ Scan interrupted by user!")
    except Exception as e:
        print(Fore.RED + f"\n❌ An error occurred: {str(e)}")

if __name__ == "__main__":
    try:
        import pyfiglet
        import colorama
        import requests
    except ModuleNotFoundError:
        print("Required modules not found. Installing...")
        os.system("pip install pyfiglet colorama requests")

    main()

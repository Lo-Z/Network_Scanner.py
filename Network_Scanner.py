# ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~
#
# Network_Scanner 2.0 will look for App IPs and MACs on a network and drop its output in a notepad txt file on the Desktop
# Developed originally for Audiovisual & Network Administration and finding devices on a network 
# Corporate computers that use a OneDrive couldn't run the original 1.11 release, thus an update was required
#
# Arp Cache Dump requires Admin Priv, else the scan may show old cached IPs from a prior network 
#
# ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~ <(-.-)> ~

# Version 2.0 (working model)

import subprocess
import os
import glob
import ctypes

print("Getting Computer Info")
# Get the base user profile directory
user_profile = os.path.expanduser("~")

# Possible desktop paths
standard_desktop = os.path.join(user_profile, "Desktop")
onedrive_desktop = os.path.join(user_profile, "OneDrive", "Desktop")

# Detect corporate OneDrive dynamically
corporate_onedrive_dirs = glob.glob(os.path.join(user_profile, "OneDrive -*"))
corporate_onedrive_desktop = None

for corp_dir in corporate_onedrive_dirs:
    possible_desktop = os.path.join(corp_dir, "Desktop")
    if os.path.exists(possible_desktop):
        corporate_onedrive_desktop = possible_desktop
        break  # Stop after finding the correct one

# Choose the correct desktop path
if os.path.exists(standard_desktop):
    desktop_path = os.path.join(standard_desktop, "network_results.txt")
elif os.path.exists(onedrive_desktop):
    desktop_path = os.path.join(onedrive_desktop, "network_results.txt")
elif corporate_onedrive_desktop:
    desktop_path = os.path.join(corporate_onedrive_desktop, "network_results.txt")
else:
    raise FileNotFoundError("Could not find a valid Desktop directory.")

# Ensures no previous jobs exist
close_all_jobs = subprocess.run(["powershell", "-Command", "Get-Job | Remove-Job -Force"], shell=True)  
print("Preping Background Scan")

# Function to check if running as admin
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# Ask user if they want to flush DNS
clear_dns = input("Do you want to flush DNS & APR cache? You might see old IPs if you don't. Admins Only (y/n): ").strip().lower()
if clear_dns == "y":
    subprocess.run(["powershell", "-Command", "ipconfig /flushdns"], shell=True)
    
    if is_admin():
        subprocess.run(["powershell", "-Command", "arp -d *"], shell=True)  # Clears ARP table
        subprocess.run(["powershell", "-Command", "netsh interface ip delete arpcache"], shell=True)  # Resets ARP cache
        print("DNS and ARP cache flushed successfully!")
    else:
        print("Skipping ARP cache clearing. Run as administrator to clear ARP entries.")


# pinging all IPs to Cache
ping_em_all = subprocess.run([
    "powershell", "-Command",
    "$subnet = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin -ne 'WellKnown' }).IPAddress -replace '\\.\\d+$','.'; "
    "1..254 | ForEach-Object { Test-Connection -ComputerName ($subnet + $_) -Count 1 -AsJob }; "
    "Get-Job | Wait-Job | Remove-Job -Force"
], shell=True)

# PowerShell command to get only IPv4 addresses and MAC addresses, removing IPv6
powershell_command = (
    "Get-NetNeighbor | Where-Object {($_.IPAddress -match '\\d+\\.\\d+\\.\\d+\\.\\d+') -and ($_.LinkLayerAddress -ne '00-00-00-00-00-00')} "
    "| Select-Object -Property IPAddress, LinkLayerAddress "
    "| Format-Table -HideTableHeaders"
)
print("Collecting IP's ~<(-.-)>~")

# Run the PowerShell command and capture output
netscan = subprocess.run(["powershell", "-Command", powershell_command], capture_output=True, text=True, shell=True)

# Process the output to clean up formatting
output_lines = netscan.stdout.strip().split("\n")
cleaned_data = []
for line in output_lines:
    line = line.strip()
    if not line or line.startswith("---"):
        continue
    ip_mac = line.split()
    if len(ip_mac) == 2:
        ip, mac = ip_mac
        if not (ip.startswith("224.") or ip.startswith("239.") or ip.startswith("255.") or ip.endswith("255.") or ip == "127.0.0.1"): 
            print("Parsing New Data (>^-^<)")
          

            # Resolve hostname using PowerShell
            hostname_command = f"Resolve-DnsName -Name {ip} -ErrorAction SilentlyContinue | Select-Object -ExpandProperty NameHost"
            hostname_result = subprocess.run(["powershell", "-Command", hostname_command], capture_output=True, text=True, shell=True)
            hostname = hostname_result.stdout.strip() if hostname_result.stdout.strip() else "Unknown-Hostname"
            
            # Get MAC Address Vendor using API first
            print("New IP Found, Getting Hostname & Mac Vendor Info Online")
            try:
                mac_vendor_command = f"(Invoke-WebRequest -Uri 'https://api.macvendors.com/{mac}' -UseBasicParsing).Content"
                mac_vendor_result = subprocess.run(["powershell", "-Command", mac_vendor_command], capture_output=True, text=True, shell=True)
                mac_vendor = mac_vendor_result.stdout.strip() if mac_vendor_result.stdout.strip() else "Unknown-Vendor"
            except Exception:
                mac_vendor = "Unknown-Vendor"
            
            # If API failed, try local lookup
            print("Couldn't get Hostname & Mac Vendor Info Online, Checking Locally <(^-^'<)")
            if mac_vendor == "Unknown-Vendor":
                local_mac_vendor_command = f"(Get-CimInstance Win32_NetworkAdapter | Where-Object {{ $_.MACAddress -eq '{mac}' }} | Select-Object -ExpandProperty Name)"
                local_mac_vendor_result = subprocess.run(["powershell", "-Command", local_mac_vendor_command], capture_output=True, text=True, shell=True)
                mac_vendor = local_mac_vendor_result.stdout.strip() if local_mac_vendor_result.stdout.strip() else "Unknown-Vendor"

            # Get network adapter type (Ethernet, Wi-Fi)
            print("Getting Adapter Info Maybe !(>^o^)> (>-.-<)")
            adapter_command = f"Get-NetAdapter | Where-Object {{ $_.MacAddress -replace '-', ':' -eq '{mac.replace('-', ':')}' }} | Select-Object -ExpandProperty MediaType"
            adapter_result = subprocess.run(["powershell", "-Command", adapter_command], capture_output=True, text=True, shell=True)
            adapter_type = adapter_result.stdout.strip() if adapter_result.stdout.strip() else "Unknown-Adapter"

            cleaned_data.append(f"{hostname} ---> {ip} ---> {mac} ---> {mac_vendor} ---> {adapter_type}")

# Save to desktop
print("Saving to Desktop, Standby for Opening File")
with open(desktop_path, "w") as file:
    file.write("\n\n".join(cleaned_data) + "\n\n")

print(f"Network scan completed. Results saved to: {desktop_path}")

# Open the file automatically
subprocess.run(["notepad.exe", desktop_path])

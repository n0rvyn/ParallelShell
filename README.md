#### Usage

```
Usage:

  mminit.py [module] [options] [action]

Modules:

  ipcalc - calculate subnet for given <IP/Prefix> | [Netmask]
    mminit.py ipcalc 192.168.0.1/24
    mminit.py ipcalc 192.168.0.1 24
    mminit.py ipcalc 192.168.0.1/255.255.255.0
    mminit.py ipcalc 192.168.0.1 255.255.255.0

  ifcfg - automatically assign IP address[es] to the first suitable interface
    mminit.py ifcfg -h 192.168.1.1/2 -a 10.10.10.1/2=28 -g '10.10.10.14' 
				    -p 'SHARED_PASS' --default-route --restart-network
    mminit.py ifcfg 
        <-h HOST[s]> 
        [-u USER[s]] [-p PASSWORD[s]]
        <-a ADDRESS[es]> <-g GATEWAY[s]>
        [-r | --default-route] [-w | --restart-network]
        [--preview]
	mminit.py ifcfg    
		<-h HOST[s]>   
	    [-u USER[s]] [-p PASSWORD[s]]  
	    <-i interface> --show

  gpfs - create GPFS cluster, NSD, filesystem
    mminit.py gpfs 
        <-h HOST[s]> 
        [-u USER[s]] [-p PASSWORD[s]]
        [-s ADDRESSES] [-b HEARTBEATS] [-n HOSTNAMES] [-x PREFIX] 
        [-f DIRECTORY] [-g MMFS] [-d /dev/sdx] 
        [-P PRIMARY] [-s SECONDARY] 
        <--preview | --run>

  multerm -- cli for fetching output of command from multiple hosts
    mminit.py multerm
        <-h HOST[s]>
        [-u USER[s]] [-p PASSWORD[s]]  

Options:

  -h HOST[s]            address[es] or domain[s] to login via SSH, 
                        '192.168.1.1/2' or '192.168.1.1, 192.168.1.2'
  -u USER[s]            username[s] of the host[s], the default value is 'root' 
						'USER1, USER2 ...'
  -p PASSWORD[s]        password[s] of the user[s] 'PASS1 PASS2'
                        one string for all
                         or specify every different PASSWORD for each

  For module ifcfg only:
  -a ADDRESSES          address[es] to be assigned
                        format 1: '192.168.1.1/24, 192.168.1.2/24'
                        format 2: '192.168.1.1/2=24'
  -g GATEWAY[s]         gateway[s] for the address[es] to be assigned
						such as '192.168.1.1, 192.168.2.1'
  -t, --default-route   set the GATEWAY specified default 
  -r, --restart-network restart service 'network' via 'systemctl restart network' 
  -i INTERFACE          name of network interface card

  
  For module gpfs only:
  -s ADDRESSES          service IP addresses '192.168.1.1/2, 192.168.2.1/2'
                        prefix of address such as '192.168' is acceptable 
	                    for verifying network configuration
                        both of prefix and full address are used to identified 
                        host, assigning IP with '-a' option
  -b HEARTBEATS         heartbeats IP addresses '192.168.1.1/2, 192.168.2.1/2'
                        prefix of address such as '192.168' is acceptable 
                        for verifying network configuration
                        both of prefix and full address are used to identified 
                        host, assigning IP with '-a' option
  -n [DC:]HOST[/HOST]   hostnames 
						'DATACENTER1:host1/host2, DATACENTER2:host3/host4'
                        for double checking host configuration
                        never try to set hostname here

  -x PREFIX             nodename prefix, append to the beginning of 
						the OS hostname 'prefix-'
                        this option overwrite the global parameter 
                        defined at the beginning 

  -m MOUNT_POINT        GPFS filesystem mount point
  -f FS_NAME            the name of GPFS filesystem
  -d DISK               the name of hard driver used for create NSD

  -P NODENAME           the primary node of the GPFS cluster
  -S NODENAME           the secondary node of the cluster
  -Q NODENAME           the 3-party node of the cluster
						quorum only, never supply NSD service
 
Actions:
  --show                display NICs configuration
  --preview             preview generated configuration for GPFS installation
  --help                print help messages and exit
```


#### Required
- RHEL 7.9
- Python >= 3.6.8
	- paramiko-2.11.0
	- bcrypt-3.2.2
	- cryptography-36.0.2
	- PyNaCl-1.5.0
	- six-1.16.0
	- cffi-1.15.1
	- pycparser-2.21
	- pip-21.3.1
	- wheel-0.37.1
	- setuptools_rust-1.1.2
	- semantic_version-2.10.0
	- typing_extensions-4.1.1
	- setuptools-59.6.0
	- cryptography-36.0.2
---

#### Install Required Packages
`# yum install -y python3 python3-pip`
`# python3 -m pip install upgrade pip`
`# python3 -m pip install cryptography==36.0.2`
`# python3 -m pip install paramiko`

---
##### MultiTerm(hosts: tuple, debug=False):
\__init__()
<pre>
Create a multiple terminal interface.

<b>Parameters: hosts</b> (<i>tuple</i>) - ((host, user, password, port), (None, ), ('', ))
			<b>debug</b>: set to True display log on the monitor
</pre>
 getoutput(command: str)
<pre>
Execute command and fetch output for all hosts specified

<b>Parameters: command</b> (<i>str</i>) - command line
<b>Returns:</b>	a <i>list</i> of output strings the command being executing, ordering by the sequence of the hosts defined before.</pre>

getstatusoutput(command: str)
<pre>
Execute command and fetch return code & output for every host

<b>Parameters: command</b> (<i>str</i>) - command line
<b>Returns:</b> 	a list of 2-tuple which contains the return code and output string of the executing command, be ordered by the sequence of the hosts.
</pre>

getoutput_thread(command: str)
<pre>
Execute command and fetch output with multiple threads

<b>Parameters: command</b> (<i>str</i>) - command line string
<b>Returns:</b>	a <i>dict</i> takes [host|address][s] as the key[s], and the output string[s] as the value[s]
</pre>

getstatusoutput_thread(command: str)
<pre>
Execute command and fetch return code & output for every host with multiple threads

<b>Parameters: command</b> (<i>str</i>) - command line string
<b>Returns:</b> 	a <i>dict</i> take [host|address][s] as the key[s], and 2-tuple[s] of command executing return code and output string as the value[s]
</pre>

getstatus_bool(command: str)
<pre>
Execute command and fetch return code with multiple threads

<b>Parameters: command</b> (<i>str</i>) - command line string
<b>Returns:</b> 	a <i>dict</i> take [host|address][s] as the key[s], and command executing return status (True | False) as the value[s]
</pre>

add_hosts(ip: str, host_name: str):
<pre>
append line 'address host_name' to file '/etc/hosts'  

<b>Returns:</b>    return code[s] of `echo "ip  host" >> /etc/hosts`
</pre>

add_ssh_key(ssh_pub_key)
<pre>
Append specified ssh public key to each host  

<b>Parameters: ssh_pub_key </b>(<i>str</i>) - ssh public key
</pre>

gen_ssh_key(ssh_key_file=None)
<pre>
Check ssh key file, if not exist, generate by command `ssh-keygen -t rsa`
</pre>

add_hosts_all(ip_prefix: str, nodename_prefix=None)
<pre>
Add 'ip hostname' string[s] to all hosts defined

<b><i>'localhost' is ignored!!! </b></i>

<b>Parameters: ip_prefix </b>(<i>str</i>) - the prefix if IP address[es]
			<b>nodename_prefix</b> (<i>str</i>) - the prefix of nodename[s] to be appended. 

For example: 
ip_prefix = '192.168', nodename_prefix = 'rhel-'
one NIC of the host which has the hostname 'server01' hold the IP '192.168.1.1'
line '192.168.1.1  rhel-server01' will be appended to the file '/etc/hosts' on every host
</pre>

add_known_hosts(*host)
<pre>
Add host[s] to SSH known_hosts file
  
<b>Parameters: host:</b> hostname [or|and] IP address
</pre>

add_known_hosts_all(self, ip_prefix: str, nodename_prefix=None)
<pre>
Add both IP address[es] with prefix 'ip_prefix' and nodename[s] with prefix 'nodename_prefix' to SSH known_hosts file  

<b>Parameters: ip_prefix:</b> (<i>str</i>) prefix of IP address
			<b>nodename_prefix: </b>(<i>str</i>) prefix of nodename
</pre>

add_ssh_whitelist(address)
<pre>append IP address to file '/etc/hosts.allow'</pre>

add_ssh_whitelist_all(ip_prefix: str)
<pre>append addresses those start with 'ip_prefix' to file '/etc/hosts.allow'</pre>

ssh_authorize_all(ssh_key_file=None, add_known_hosts=False)
<pre>configure SSH key-based authentication for all hosts by each other</pre>

assign_ip_to_nic_thread(*ip_addr_with_prefix, gateways: str,  default_route=False, add_static_routes=False, nic_prefix=None, nic_ignore_prefix=None, restart_network=False, backup=False):  
<pre>
try assign IP addresses to the first suitable interface on the hosts

<b>Parameters: ip_addr_with_prefix</b> - list of addresses/prefix has the same sequence of the hosts
			<b>gateways</b>(<i>str</i>) - one or more gateway be separated by ','
			<b>default_route</b> (<i>bool</i>) - set to True add 'DEFROUTE' line to ifcfg file
			<b>add_static_routes</b> (<i>bool</i>) - set to True add static routes for the IPs read from 'ip_addr_with_prefix'
			<b>nic_prefix</b> (<i>str</i>) - pick up the NICs those names start with this prefix
			<b>nic_ignore_prefix</b> (<i>str</i>) - ignore the NICs those names start with this 
			<b>restart_network</b> (<i>bool</i>) - True of False to decide weather restart the service 'network' via command 'systemctl restart network'
			<b>backup</b> (<i>bool</i>) - set to True to backup ifcfg files before do any changes

<b>Returns:</b> 	[(ip_addr, correct_nic)...]</pre>


add_static_route(target_addr_with_prefix, source_gateway)
<pre>add static route for 'target_addr_with_prefix' via 'source_gateway'</pre>

set_timezone(timezone='Asia/Shanghai')
<pre>set timezone for system, default is 'Asia/Shanghai'</pre>

disable_ssh_dns(self)
<pre>disable SSH service 'useDNS' for all hosts</pre>

add_yum_repo(baseurl, repo_name='rhel', repo_desc='RHEL Base Repo')
<pre>configure YUM repository with 'baseurl' and name 'rhel'</pre>

ipcalc(address, netmask='24')
<pre>calculate IP subnet for the address specified

<b>Returns: </b>	network id, the 1st IP, the last IP, broadcast, number of hosts, as a 5-tuple</pre>

#### Usage
```
Usage:  
  mminit.py [module] [options] [action]  

Modules:  
  ipcalc - calculate subnet for given <IP/Prefix> | [Netmask]                   
  ifcfg - automatically assign IP address[es] to the first suitable interface[s]
```

```
mminit.py ipcalc 192.168.0.1/24    
mminit.py ipcalc 192.168.0.1 24    
mminit.py ipcalc 192.168.0.1/255.255.255.0    
mminit.py ipcalc 192.168.0.1 255.255.255.0 
mminit.py ifcfg -l 192.168.1.1/2 -o 10.10.10.1/2=28 -g '10.10.10.14' -s 'PASS'
```

#### 示例：

![[Screen Shot 2022-07-24 at 16.29.08.png]]
![[Screen Shot 2022-07-24 at 16.38.27.png]]
![[Screen Shot 2022-07-24 at 16.41.08.png]]
![[Screen Shot 2022-07-24 at 16.43.29.png]]
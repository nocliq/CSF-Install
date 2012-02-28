#!/bin/bash

TEMPDIR="/root/tmp/csf"
BACKUPDIR="/root/csf-bak/"

initialize() {
	if [ ! -d $TEMPDIR ]; then mkdir -p $TEMPDIR; fi
	cd $TEMPDIR;

	if [ -d "/etc/csf" ]; then 
		echo "Previous CSF detected! Backing up to /root/csf-bak"
		mkdir -p $BACKUPDIR
		tar czpvf $BACKUPDIR/csf-bak-`date +%s`.tar.gz /etc/csf/ &>/dev/null
	fi
}

stop_current() {
	if [ -e /etc/init.d/csf ]; then
		echo "Stopping CSF"
		#/etc/init.d/csf stop &>/dev/null
		echo "OK"
	fi
	if [ -e /etc/init.d/lfd ]; then
		echo "Stopping LFD"
		#/etc/init.d/lfd stop &>/dev/null
		echo "OK"
	fi
}

install_csf() {
	cd $TEMPDIR
	wget  -O $TEMPDIR/csf.tgz "http://configserver.com/free/csf.tgz"
	tar xzf ./csf.tgz 
	cd ./csf/
	echo "Running installer."
	./install.sh &>/dev/null
	echo "Installer finished..."
}

config_csf() {

	# Add Local IPs, DNS resolvers, Gateway, Wizard and home IP to csf.allow
	echo "Configuring csf.allow..."
	# local IPs added unconditionally
	echo "Adding local IPs:"
	for IP in $(ifconfig | grep -E "^ +inet addr:" | awk '{print $2}' | awk -F: '{print $2}'); do
		if [ ! `grep -E "^$IP" /etc/csf/csf.allow` &>/dev/null ]; then
			echo -e "\tAdding $IP to /etc/csf/csf.allow"
            echo "$IP # local IP (do not remove)" >> /etc/csf/csf.allow
		else
			echo -e "\t$IP already in csf.allow, skipping."
		fi
	done

	# Gateway
	echo "Adding Gateway:"
    for IP in $(grep -E "^GATEWAY=" /etc/sysconfig/network-scripts/ifcfg* | awk -F= '{print $2}'); do
        if [ ! `grep -E "^$IP " /etc/csf/csf.allow` &>/dev/null ]; then
            echo -e "\tAdding $IP to /etc/csf/csf.allow"
            echo "$IP # Gateway (do not remove)" >> /etc/csf/csf.allow
        else
            echo -e "\t$IP already in csf.allow, skipping."
        fi
    done


	# resolvers -- add only for port 53 (TCP/UDP)
	echo "Adding Resolvers:"
	for IP in $(grep -E "^nameserver " /etc/resolv.conf | awk '{print $2}'); do
			if [ ! `grep -E "^$IP" /etc/csf/csf.allow` &>/dev/null ]; then
			echo -e "\tAdding $IP to /etc/csf/csf.allow"
			echo "$IP:tcp:in:s=53 # DNS Server (do not remove)" >> /etc/csf/csf.allow
			echo "$IP:udp:in:s=53 # DNS Server (do not remove)" >> /etc/csf/csf.allow 
			echo "$IP:tcp:out:s=53 # DNS Server (do not remove)" >> /etc/csf/csf.allow
			echo "$IP:udp:out:s=53 # DNS Server (do not remove)" >> /etc/csf/csf.allow
		else
			echo -e "\t$IP already in csf.allow, skipping."
		fi
	done
		
	# Add My IP
	echo "Adding my IP (austin.rr.com):"
    for IP in 70.129.69.0/24; do
        if [ ! `grep -E "^$IP " /etc/csf/csf.allow` &>/dev/null ]; then
            echo -e "\tAdding $IP to /etc/csf/csf.allow"
            echo "$IP # My IP - austin.rr.com" >> /etc/csf/csf.allow
        else
            echo -e "\t$IP already in csf.allow, skipping."
        fi
    done

	# Add My IP
    echo "Adding Wizard2:"
    for IP in 70.87.80.194/32; do
        if [ ! `grep -E "^$IP " /etc/csf/csf.allow` &>/dev/null ]; then
            echo -e "\tAdding $IP to /etc/csf/csf.allow"
            echo "$IP # Wizard2 IP" >> /etc/csf/csf.allow
        else
            echo -e "\t$IP already in csf.allow, skipping."
        fi
    done


	# Add local IPs, DNS resolver, Gateway Wizard and home IP to csf.ignore

	# Add common web crawlers to csf.rignore (Experimental)

	# Add MySQL, PostgreSQL to csf.pignore
	
	# Add certain files for directory watching to ignore? (Horde?)

	# For my server, add my username to csf.suignore

	# Edit csf.conf
	
}

cleanup() {
	rm -rf $TEMPDIR
}

debug() {
	echo -e "\n\n"
	echo "DEBUG =>"
	echo -e "\n\n"
	ls -lah $TEMPDIR $BACKUPDIR
	
	
	echo 
	LFDPID=$(pgrep lfd)
	if [ ! -z $LFDPID ]; then echo "LFD is running. PID= $LFDPID"; fi

	CSFRULES=$(csf -l | wc -l)
	if [ -e /etc/init.d/csf ] && [ $CSFRULES > 20 ]; then echo "CSF is running with $CSFRULES rules."; fi

	echo
	echo "csf.allow:"
	grep -E "^[0-9]{1,3}" /etc/csf/csf.allow



}


#initialize
#stop_current
#install_csf
config_csf
#update_csf
#restart_csf
#cleanup
debug



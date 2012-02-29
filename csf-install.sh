#!/bin/bash

TEMPDIR="/root/tmp/csf"
BACKUPDIR="/root/csf-bak/"

initialize() {
	if [ ! -d $TEMPDIR ]; then mkdir -p $TEMPDIR; fi
	cd $TEMPDIR;

	if [ -d "/etc/csf" ]; then 
		echo "Previous CSF detected! Backing up to /root/csf-bak"
		mkdir -p $BACKUPDIR &>/dev/null
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
	sh install.sh &>/dev/null
	if [ "0" = "$?" ]; then
		echo "Installer finished..."
	else
		echo "Failed"
		exit 2
	fi
}

config_csf() {

####	
#  CSF.ALLOW: a list of IP's and CIDR addresses that should always be allowed through the firewall
####
	# Add Local IPs, DNS resolvers, Gateway, Wizard and home IP to csf.allow
	echo "Configuring csf.allow..."
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

	# DNS resolvers -- add only for port 53 (TCP/UDP)
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
		
	# Add My Home IP
	echo "Adding my IP (austin.rr.com):"
    for IP in 70.129.69.0/24; do
        if [ ! `grep -E "^$IP " /etc/csf/csf.allow` &>/dev/null ]; then
            echo -e "\tAdding $IP to /etc/csf/csf.allow"
            echo "$IP # My IP - austin.rr.com" >> /etc/csf/csf.allow
        else
            echo -e "\t$IP already in csf.allow, skipping."
        fi
    done

	# Add Wiz2 IP
    echo "Adding Wizard2:"
    for IP in 70.87.80.194/32; do
        if [ ! `grep -E "^$IP " /etc/csf/csf.allow` &>/dev/null ]; then
            echo -e "\tAdding $IP to /etc/csf/csf.allow"
            echo "$IP # Wizard2 IP" >> /etc/csf/csf.allow
        else
            echo -e "\t$IP already in csf.allow, skipping."
        fi
    done

###
# CSF.IGNORE: a list of IP's and CIDR addresses that lfd should ignore and not block if detected
###

	# Add local IPs, DNS Server, Gateway Wizard and home IP to csf.ignore
	echo
	echo "Configuring csf.ignore..."
	# Gateway
    echo "Adding Gateway:"
    for IP in $(grep -E "^GATEWAY=" /etc/sysconfig/network-scripts/ifcfg* | awk -F= '{print $2}'); do
        if [ ! `grep -E "^$IP " /etc/csf/csf.ignore` &>/dev/null ]; then
            echo -e "\tAdding $IP to /etc/csf/csf.ignore"
            echo "$IP # Gateway (do not remove)" >> /etc/csf/csf.ignore
        else
            echo -e "\t$IP already in csf.ignore, skipping."
        fi
    done

    # local IPs added unconditionally
    echo "Adding local IPs:"
    for IP in $(ifconfig | grep -E "^ +inet addr:" | awk '{print $2}' | awk -F: '{print $2}'); do
        if [ ! `grep -E "^$IP" /etc/csf/csf.ignore` &>/dev/null ]; then
            echo -e "\tAdding $IP to /etc/csf/csf.ignore"
            echo "$IP # local IP (do not remove)" >> /etc/csf/csf.ignore
        else
            echo -e "\t$IP already in csf.ignore, skipping."
        fi
    done

###
# CSF.DENY: a list of IP's and CIDR addresses that should never be allowed through the firewall
###

    # Non-Routable Addresses
	echo
	echo "Configuring csf.deny..."
	
	# 10.0.0.0/8
    echo "Adding Non-Routable Addresses:"
    if [ ! `grep -E "^10." /etc/csf/csf.deny` &>/dev/null ]; then
        echo -e "\tAdding 10.0.0.0/8 to /etc/csf/csf.deny"
        echo "10.0.0.0/8 # Non-Routable Address Space" >> /etc/csf/csf.deny
    else
        echo -e "\t10.0.0.0/8 already in csf.deny, skipping."
    fi
    
	# 172.16.0.0/16
	if [ ! `grep -E "^172.16" /etc/csf/csf.deny` &>/dev/null ]; then
        echo -e "\tAdding 172.16.0.0/16 to /etc/csf/csf.deny"
        echo "172.16.0.0/16 # Non-Routable Address Space" >> /etc/csf/csf.deny
    else
        echo -e "\t172.16.0.0/16 already in csf.deny, skipping."
    fi
	
	# 169.254.0.0/16
	if [ ! `grep -E "^169.254" /etc/csf/csf.deny` &>/dev/null ]; then
        echo -e "\tAdding 169.254.0.0/16 to /etc/csf/csf.deny"
        echo "169.254.0.0/16 # Non-Routable Address Space" >> /etc/csf/csf.deny
    else
        echo -e "\t169.254.0.0/16 already in csf.deny, skipping."
    fi
	
	# 192.168.0.0/16
	if [ ! `grep -E "^192.168" /etc/csf/csf.deny` &>/dev/null ]; then
        echo -e "\tAdding 192.168.0.0/16 to /etc/csf/csf.deny"
        echo "192.168.0.0/16 # Non-Routable Address Space" >> /etc/csf/csf.deny
    else
        echo -e "\t192.168.0.0/16 already in csf.deny, skipping."
    fi

###
# CSF.RIGNORE
###
	
# Add common web crawlers to csf.rignore (Experimental)

# The following is a list of domains and partial domain that lfd process
# tracking will ignore based on reverse and forward DNS lookups. An example of
# its use is to prevent web crawlers from being blocked by lfd, e.g.
# .googlebot.com and .crawl.yahoo.net
#

	echo
    echo "Configuring csf.rignore..."

	# Googlebot
	if [ ! `grep -E "^\.googlebot\.com" /etc/csf/csf.rignore` &>/dev/null ]; then
        echo -e "\tAdding GoogleBot to /etc/csf/csf.rignore"
        echo ".googlebot.com # GoogleBot" >> /etc/csf/csf.rignore
    else
        echo -e "\tGoogleBot already in csf.rignore, skipping."
    fi

	# Yahoo! Crawler
    if [ ! `grep -E "^\.crawl\.yahoo\.com" /etc/csf/csf.rignore` &>/dev/null ]; then
        echo -e "\tAdding Yahoo! Crawler to /etc/csf/csf.rignore"
        echo ".crawl.yahoo.com # Yahoo! Crawler" >> /etc/csf/csf.rignore
    else
        echo -e "\tYahoo! Crawler already in csf.rignore, skipping."
    fi

###
# CSF.PIGNORE
###

    echo
    echo "Configuring csf.pignore..."

	# Add MySQL, PostgreSQL to csf.pignore
    # MySQL
    if [ ! `grep -i "/usr/sbin/mysqld" /etc/csf/csf.pignore` &>/dev/null ]; then
        echo -e "\tAdding MySQL to /etc/csf/csf.pignore"
        echo "exe:/usr/sbin/mysqld # MySQL" >> /etc/csf/csf.pignore
    else
        echo -e "\tMySQL already in csf.pignore, skipping."
    fi

	# PostgreSQL
    if [ ! `grep -i "/usr/bin/postmaster" /etc/csf/csf.pignore` &>/dev/null ]; then
        echo -e "\tAdding PostgreSQL to /etc/csf/csf.pignore"
        echo "exe:/usr/bin/postmaster # PostgreSQL" >> /etc/csf/csf.pignore
    else
        echo -e "\tPostgreSQL already in csf.pignore, skipping."
    fi

###
# CSF.DIRWATCH
###

    echo
    echo "Configuring csf.dirwatch..."

	# SSHD config
    if [ ! `grep -E "^/etc/ssh/sshd_config" /etc/csf/csf.dirwatch` &>/dev/null ]; then
        echo -e "\tAdding SSHD config to /etc/csf/csf.dirwatch"
        echo "/etc/ssh/sshd_config" >> /etc/csf/csf.dirwatch
    else
        echo -e "\tSSHD Config already in csf.dirwatch, skipping."
    fi

	# csf.suignore
    if [ ! `grep -E "^/etc/csf/csf.suignore" /etc/csf/csf.dirwatch` &>/dev/null ]; then
        echo -e "\tAdding csf.suignore to /etc/csf/csf.dirwatch"
        echo "/etc/csf/csf.suignore" >> /etc/csf/csf.dirwatch
    else
        echo -e "\tcsf.suignore already in csf.dirwatch, skipping."
    fi

	# csf.ignore
    if [ ! `grep -E "^/etc/csf/csf.ignore" /etc/csf/csf.dirwatch` &>/dev/null ]; then
        echo -e "\tAdding csf.ignore to /etc/csf/csf.dirwatch"
        echo "/etc/csf/csf.ignore" >> /etc/csf/csf.dirwatch
    else
        echo -e "\tcsf.ignore already in csf.dirwatch, skipping."
    fi




# Add certain files for directory watching to ignore? (Horde?)
# For my server, add my username to csf.suignore

###
# CSF.CONF
###
		echo
		echo "Editing: /etc/csf/csf.conf"
        echo -e "\tSetting TESTING=0"
        sed -ie "s/^TESTING = .*/TESTING = \"0\"/g" /etc/csf/csf.conf

        echo -e "\tSetting AUTO_UPDATES=1"
        sed -ie "s/^AUTO_UPDATES = .*/AUTO_UPDATES = \"1\"/g" /etc/csf/csf.conf

        echo -e "\tSetting LF_TRIGGER_PERM to 15 minutes (default)"
        sed -ie "s/^LF_TRIGGER_PERM = .*/LF_TRIGGER_PERM = \"900\"/g" /etc/csf/csf.conf

        echo -e "\tSetting SSH failure to 20 / 30 min ban"
        sed -ie "s/^LF_SSHD = .*/LF_SSHD = \"20\"/g" /etc/csf/csf.conf
        sed -ie "s/^LF_SSHD_PERM = .*/LF_SSHD_PERM = \"3600\"/g" /etc/csf/csf.conf

        echo -e "\tSetting SMTP failure rate to 20 / 5 min ban"

        sed -ie "s/^LF_SMTPAUTH = .*/LF_SMTPAUTH = \"20\"/g" /etc/csf/csf.conf
        sed -ie "s/^LF_SMTPAUTH_PERM = .*/LF_SMTPAUTH_PERM = \"300\"/g" /etc/csf/csf.conf

        echo -e "\tSetting POP3 failure rate to 20 / 5min ban"
        sed -ie "s/^LF_POP3D = .*/LF_POP3D = \"20\"/g" /etc/csf/csf.conf
        sed -ie "s/^LF_POP3D_PERM = .*/LF_POP3D_PERM = \"300\"/g" /etc/csf/csf.conf

        echo -e "\tSetting HTTP auth failure detection to 0 (disabled)"
        sed -ie "s/^LF_HTACCESS = .*/LF_HTACCESS = \"0\"/g" /etc/csf/csf.conf
        sed -ie "s/^LF_HTACCESS_PERM = .*/LF_HTACCESS_PERM = \"300\"/g" /etc/csf/csf.conf

        echo -e "\tSetting MODSEC failure detection to 0 (disabled)"
        sed -ie "s/^LF_MODSEC = .*/LF_MODSEC = \"0\"/g" /etc/csf/csf.conf
        sed -ie "s/^LF_MODSEC_PERM = .*/LF_MODSEC_PERM = \"300\"/g" /etc/csf/csf.conf

        echo -e "\tSetting cPanel login failures to 15 / 15min ban"
        sed -ie "s/^LF_CPANEL = .*/LF_CPANEL = \"15\"/g" /etc/csf/csf.conf
        sed -ie "s/^LF_CPANEL_PERM = .*/LF_CPANEL_PERM = \"3600\"/g" /etc/csf/csf.conf

        echo -e "\tSetting suhosin detection to 0 (disabled)"
        sed -ie "s/^LF_SUHOSIN = .*/LF_SUHOSIN = \"0\"/g" /etc/csf/csf.conf
        sed -ie "s/^LF_SUHOSIN_PERM = .*/LF_SUHOSIN_PERM = \"180\"/g" /etc/csf/csf.conf

        echo -e "\tSetting LF_SPAMHAUS=604800" # 1 day ban if on SpamHaus list
        sed -ie "s/^LF_SPAMHAUS = \"0\"/LF_SPAMHAUS = \"86400\"/g" /etc/csf/csf.conf

        echo -e "\tSetting CT_LIMIT=300"
        sed -ie "s/^CT_LIMIT = .*/CT_LIMIT = \"300\"/g" /etc/csf/csf.conf

        echo -e "\tSetting CT_BLOCK_TIME=900"
        sed -ie "s/^CT_BLOCK_TIME = .*/CT_BLOCK_TIME = \"900\"/g" /etc/csf/csf.conf

        echo -e "\tSetting LF_SCRIPT_ALERT=1000"
        sed -ie "s/^LF_SCRIPT_ALERT = .*/LF_SCRIPT_ALERT = \"1000\"/g" /etc/csf/csf.conf

		echo -e "\tSetting LF_DSHIELD=86400"
        sed -ie "s/LF_DSHIELD = \"0\"/LF_DSHIELD = \"86400\"/g" /etc/csf/csf.conf

        echo -e "\tDisabling email warning for SSH login"
        sed -ie "s/^LF_SSH_EMAIL_ALERT = \"1\"/LF_SSH_EMAIL_ALERT = \"0\"/g" /etc/csf/csf.conf

        echo -e "\tConnection Tracking Options"
        echo -e "\t\tSetting CT_INTERVAL=120"
        sed -ie "s/^CT_INTERVAL = .*/CT_INTERVAL = \"120\"/g" /etc/csf/csf.conf

        echo -e "\t\tSetting connection blocks to temporary"
        sed -ie "s/^CT_PERMANENT = .*/CT_PERMANENT = \"0\"/g" /etc/csf/csf.conf

        echo -e "\t\tSetting blocktime to 30 minutes"
        sed -ie "s/^CT_BLOCK_TIME = .*/CT_BLOCK_TIME = \"1800\"/g" /etc/csf/csf.conf

        echo -e "\t\tSetting skip time_wait to on"
        sed -ie "s/^CT_SKIP_TIME_WAIT = .*/CT_SKIP_TIME_WAIT = \"1\"/g" /etc/csf/csf.conf

        echo -e "\tProcess Tracking Options"

        echo -e "\t\tSetting Process Tracking Minimum Life to 180 seconds"
        sed -ie "s/^PT_LIMIT = .*/PT_LIMIT = \"180\"/g" /etc/csf/csf.conf

        echo -e "\t\tSetting Process Tracking Check to 120 seconds"
        sed -ie "s/^PT_INTERVAL = .*/PT_INTERVAL = \"120\"/g" /etc/csf/csf.conf

        echo -e "\t\tVerifying process killing is disabled"
        sed -ie "s/^PT_USERKILL = .*/PT_USERKILL = \"0\"/g" /etc/csf/csf.conf

        echo -e "\tPortScan Options"

        echo -e "\t\tDisabling PortScan Block"
        sed -ie "s/^PS_INTERVAL = .*/PS_INTERVAL = \"0\"/g" /etc/csf/csf.conf

        echo -e "\t\tDisabling PortScan permanent blocks"
        sed -ie "s/^PS_PERMANENT = .*/PS_PERMANENT = \"0\"/g" /etc/csf/csf.conf

        echo -e "\t\tSetting Integrity check to every 8 hours (from every hour)"
        sed -ie "s/^LF_INTEGRITY = .*/LF_INTEGRITY = \"28800\"/g" /etc/csf/csf.conf

        echo -e "\tIncreasing POP3/hour from 60 to 120"
        sed -ie "s/^LT_POP3D = .*/LT_POP3D = \"120\"/g" /etc/csf/csf.conf


        echo  -e "\tSUGGESTED: SMTP_BLOCK=1 (leaving as 0 for now)"

}

uncomment_tweak() {
        if [ -z "$3" ]; then echo "uncomment_tweak requires <item> <replacement> <filename>" ; return ; fi
        if [ ! -f "$3" ]; then echo "uncomment_tweak: file does not exist ($2)" ; return ;  fi
        sed -i -e 's/^\#${1}.*/${2}/g' -e 's/${1}.*/${2}/g' "${3}"
}

config_sshd(){
 
        if [ -f "/etc/ssh/sshd_config" ]; then
                echo
				echo "Backup up original /etc/ssh/sshd_config to /etc/ssh"
				tar czpvf /etc/ssh/sshd_conf-`date +%s`.tar.gz /etc/ssh/sshd_conf &>/dev/null
				echo "Editing: /etc/ssh/sshd_config"
                echo -e "\tDisabling ssh v1"
                uncomment_tweak "Protocol " "Protocol 2" /etc/ssh/sshd_config
                echo -e "\tSetting KeySize to 2048"
                uncomment_tweak "ServerKeyBits " "ServerKeyBits 2048" /etc/ssh/sshd_config
                echo -e "\tSetting LoginGraceTime to 2m"
                uncomment_tweak "LoginGraceTime " "LoginGraceTime 2m" /etc/ssh/sshd_config
                echo -e "\tSetting MaxAuthTries 3"
                uncomment_tweak "MaxAuthTries " "MaxAuthTries 3" /etc/ssh/sshd_config
                echo -e "\tSetting UsePrivSep to yes"
                uncomment_tweak "UsePrivilegeSeparation " "UsePrivilegeSeparation yes" /etc/ssh/sshd_config
                echo -e "\tSetting MaxStartups to 5"
                uncomment_tweak "MaxStartups " "MaxStartups 5" /etc/ssh/sshd_config
        fi
                echo "Restarting: sshd"
        if [ -e "/etc/init.d/sshd" ]; then /etc/init.d/sshd restart &>/dev/null ; fi
}



set_permissions() {
    echo
	echo "Setting Folder Permissions"
	for folder in /tmp /var/tmp ; do
        echo "Setting $folder to 1777"
        chmod 1777 $folder &>/dev/null
    done
}

update_csf() {

	echo
    echo "Checking for CSF updates ..."
    echo
    /usr/sbin/csf --update
}

restart_csf() {
        if [ -e "/etc/rc.d/init.d/lfd" ]; then
                echo -n "Restarting LFD: "
                /etc/rc.d/init.d/lfd restart &>/dev/null
                echo "OK"
        fi
        if [ -e "/etc/rc.d/init.d/csf" ]; then
                echo -n "Restarting CSF: "
                /etc/rc.d/init.d/csf restart &>/dev/null
                echo "OK"

        fi
}





cleanup() {
	rm -rf $TEMPDIR
}

debug() {
	echo -e "\n\n"
	echo "DEBUG =>"
	echo -e "\n\n"
	if [ -d $TEMPDIR ]; then ls -lah $TEMPDIR $BACKUPDIR; else echo "$TEMPDIR is clean!"; fi
	
	
	echo 
	LFDPID=$(pgrep lfd)
	if [ ! -z $LFDPID ]; then echo "LFD is running. PID= $LFDPID"; fi

	CSFRULES=$(csf -l | wc -l)
	if [ -e /etc/init.d/csf ] && [ $CSFRULES -gt "20" ]; then echo "CSF is running with $CSFRULES rules."; fi

	echo
	echo "*** csf.allow:"
	grep -E "^[0-9]{1,3}" /etc/csf/csf.allow
	
	echo
    echo "*** csf.ignore:"
    grep -E "^[0-9]{1,3}" /etc/csf/csf.ignore

	echo
    echo "*** csf.deny:"
    grep -E "^[0-9]{1,3}" /etc/csf/csf.deny

	echo
    echo "*** csf.rignore:"
    grep -E "^\." /etc/csf/csf.rignore

	echo
    echo "*** csf.pignore:"
    grep -E "^exe|^user|^cmd|^pexe|^puser|^pcmd" /etc/csf/csf.pignore

	echo
    echo "*** csf.dirwatch:"
    grep -E "^\/" /etc/csf/csf.dirwatch

}


initialize
stop_current
install_csf
config_csf
config_sshd
set_permissions
update_csf
restart_csf
cleanup
debug



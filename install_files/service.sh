
DIR=/etc/nftclash
CLASH_HOME_DIR=$DIR/clash

CONFIG_PATH=$DIR/config.cfg

FILES_REPO_URL="https://raw.githubusercontent.com/SunshinePonyUwU/NftClashFiles/main"

reserve_ipv4="0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"
reserve_ipv6="::/128 ::1/128 ::ffff:0:0/96 64:ff9b::/96 100::/64 2001::/32 2001:20::/28 2001:db8::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8"

get_clash_config() {
	[ -z "$3" ] && configpath="$CLASH_HOME_DIR/config.yaml" || configpath=$3
	if [ -e "$configpath" ]; then
		eval $1=$(yq e ".$2" $configpath)
	else
		echo "$configpath does not exist!!!"
	fi
}

set_config() {
	#参数1代表变量名，参数2代表变量值,参数3即文件路径
	[ -z "$3" ] && configpath=$CONFIG_PATH || configpath=$3
	[ -n "$(grep -E "^${1}=" $configpath)" ] && sed -i "s#^${1}=\(.*\)#${1}=${2}#g" $configpath || echo "${1}=${2}" >> $configpath
}

init_config() {
	if [ -e "$CONFIG_PATH" ]; then
		source $CONFIG_PATH
	else
		echo "Creating config.cfg"
		touch $CONFIG_PATH
		echo "Generating default config"
		set_config DNS_REDIRECT 0
		set_config PROXY_COMMON_PORT_ENABLED 0
		set_config PROXY_COMMON_PORT_LIST "22,53,80,123,143,194,443,465,587,853,993,995,5222,8080,8443"
		set_config BYPASS_CN_IP_ENABLED 1
		set_config BYPASS_PASS_IP_ENABLED 1
		set_config FORCE_PROXY_IP_ENABLED 1
		source $CONFIG_PATH
	fi

	[ -z "$DNS_REDIRECT" ] && DNS_REDIRECT=0
	[ -z "$PROXY_COMMON_PORT_ENABLED" ] && PROXY_COMMON_PORT_ENABLED=0
	[ -z "$PROXY_COMMON_PORT_LIST" ] && PROXY_COMMON_PORT_LIST="22,53,80,123,143,194,443,465,587,853,993,995,5222,8080,8443"
	[ -z "$BYPASS_CN_IP_ENABLED" ] && BYPASS_CN_IP_ENABLED=0
	[ -z "$BYPASS_PASS_IP_ENABLED" ] && BYPASS_PASS_IP_ENABLED=1
	[ -z "$FORCE_PROXY_IP_ENABLED" ] && FORCE_PROXY_IP_ENABLED=1

	get_clash_config tproxy_port tproxy-port
	get_clash_config redir_port redir-port
	fwmark=$redir_port
	get_clash_config clash_dns_enabled dns.enable
	get_clash_config clash_dns_listen dns.listen

	
}

init_cn_ip_bypass() {
	if [ -n "$(grep -v '^$' "$DIR/china_ip_list.txt")" ]; then
		echo "INIT CN_IP BYPASS"
		CN_IP=$(awk '{printf "%s, ",$1}' "$DIR/china_ip_list.txt")
		nft add set inet nftclash cn_ip { type ipv4_addr\; flags interval\; } && \
		nft add element inet nftclash cn_ip {$CN_IP} && \
		nft add rule inet nftclash prerouting ip daddr @cn_ip return
	else
		echo "china_ip_list.txt is empty!!!"
		rm -f "$DIR/china_ip_list.txt"
	fi
}

init_cn_ipv6_bypass() {
	if [ -n "$(grep -v '^$' "$DIR/china_ipv6_list.txt")" ]; then
		echo "INIT CN_IP6 BYPASS"
		CN_IP6=$(awk '{printf "%s, ",$1}' "$DIR/china_ipv6_list.txt")
		nft add set inet nftclash cn_ip6 { type ipv6_addr\; flags interval\; } && \
		nft add element inet nftclash cn_ip6 {$CN_IP6} && \
		nft add rule inet nftclash prerouting ip6 daddr @cn_ip6 return
	else
		echo "china_ipv6_list.txt is empty!!!"
		rm -f "$DIR/china_ipv6_list.txt"
	fi
}

init_fw_bypass() {
	if [ "$BYPASS_CN_IP_ENABLED" = 1 ]; then
		# IPv4 Rules
		if [ -e "$DIR/china_ip_list.txt" ]; then
			init_cn_ip_bypass
		else
			echo "china_ip_list.txt does not exist!!!"
			wget -O "$DIR/china_ip_list.txt" "$FILES_REPO_URL/china_ip_list.txt"
			if [ "$?" = "0" ]; then
				chmod 777 "$DIR/china_ip_list.txt"
				init_cn_ip_bypass
			else
				echo "china_ip_list.txt download failed!!!"
			fi
		fi
		# IPv6 Rules
		if [ -e "$DIR/china_ipv6_list.txt" ]; then
			init_cn_ipv6_bypass
		else
			echo "china_ipv6_list.txt does not exist!!!"
			wget -O "$DIR/china_ipv6_list.txt" "$FILES_REPO_URL/china_ipv6_list.txt"
			if [ "$?" = "0" ]; then
				chmod 777 "$DIR/china_ipv6_list.txt"
				init_cn_ipv6_bypass
			else
				echo "china_ipv6_list.txt download failed!!!"
			fi
		fi
	fi
}

init_fw_dns() {
	dns_listen_ip=$(echo $clash_dns_listen | cut -d ":" -f 1)
	dns_listen_port=$(echo $clash_dns_listen | cut -d ":" -f 2)
	if [ "$clash_dns_enabled" = "true" ]; then
		if [ -z "$dns_listen_ip" ] || [ "$dns_listen_ip" == "0.0.0.0" ]; then
			echo "INIT DNS REDIRECT"
			nft add chain inet nftclash dns { type nat hook prerouting priority -100 \; }
			nft add rule inet nftclash dns udp dport 53 redirect to ${dns_listen_port}
			nft add rule inet nftclash dns tcp dport 53 redirect to ${dns_listen_port}
		else
			echo "You need to set the listening IP of clash dns to 0.0.0.0!!!"
		fi
	else
		echo "Clash dns is not enabled!"
	fi
	
}

init_fw() {
	nft add table inet nftclash
	nft flush table inet nftclash
	nft add chain inet nftclash prerouting { type filter hook prerouting priority 0 \; }

	RESERVED_IP="$(echo $reserve_ipv4 | sed 's/ /, /g')"
	RESERVED_IP6="$(echo $reserve_ipv6 | sed 's/ /, /g')"
	nft add rule inet nftclash prerouting ip daddr {$RESERVED_IP} return
	nft add rule inet nftclash prerouting ip6 daddr {$RESERVED_IP6} return

	[ "$PROXY_COMMON_PORT_ENABLED" = 1 ] && {
		COMMON_PORT_LIST=$(echo $PROXY_COMMON_PORT_LIST | sed 's/,/, /g')
		[ -n "$COMMON_PORT_LIST" ] && {
			nft add rule inet nftclash prerouting tcp dport != {$COMMON_PORT_LIST} return
			nft add rule inet nftclash prerouting udp dport != {$COMMON_PORT_LIST} return
		}
	}

	init_fw_bypass

	nft add rule inet nftclash prerouting meta l4proto { tcp, udp } mark set $fwmark tproxy to :$tproxy_port

	[ "$DNS_REDIRECT" = 1 ] && init_fw_dns
}

init_startup() {
	! modprobe nft_tproxy && {
		echo "missing nft_tproxy!!!"
		exit 1
	}
	if ! command -v yq >/dev/null 2>&1; then
		echo "You need to install yq!!!"
		exit 1
	fi
	if [ -e "$CLASH_HOME_DIR/clash" ]; then
		if [ -e "$CLASH_HOME_DIR/config.yaml" ]; then
			chmod 777 -R "$DIR"
			echo "INIT STARTUP DONE!"
		else
			echo "Please manually move the clash config file to $CLASH_HOME_DIR/config.yaml"
			exit 1
		fi
	else
		echo "clash file does not exist!!!"
		if [ ! -d "$CLASH_HOME_DIR" ]; then
			echo "Creating directory"
			mkdir -p "$CLASH_HOME_DIR"
			echo "Please manually restart service!"
			exit 1
		fi
		echo "Please manually move the clash executable file to $CLASH_HOME_DIR/clash"
		exit 1
	fi
}

init_started() {
	init_config
	init_fw
}

case "$1" in
  init_startup)
		init_startup
	;;
  init_started)
		init_started
	;;
	init_config)
		init_config
	;;
	init_fw)
		init_fw
	;;
esac
exit 0
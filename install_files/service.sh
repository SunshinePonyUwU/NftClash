
BLUE='\033[1;34m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NOCOLOR='\033[0m' # No Color

DIR=/etc/nftclash
TMPDIR=/tmp/nftclash
CLASH_HOME_DIR=$DIR/clash

CONFIG_PATH=$DIR/config.cfg

FILES_REPO_URL="https://ghproxy.projects.20percent.cool/https://raw.githubusercontent.com/SunshinePonyUwU/NftClashFiles/main"

reserve_ipv4="0.0.0.0/8 10.0.0.0/8 127.0.0.0/8 100.64.0.0/10 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4"
reserve_ipv6="::/128 ::1/128 ::ffff:0:0/96 64:ff9b::/96 100::/64 2001::/32 2001:20::/28 2001:db8::/32 2002::/16 fc00::/7 fe80::/10 ff00::/8"
host_ipv4=$(ubus call network.interface.lan status 2>&1 | grep \"address\" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}';)

check_command() {
	command -v sh &>/dev/null && command -v $1 &>/dev/null || type $1 &>/dev/null
}

compare(){
	if [ ! -f $1 -o ! -f $2 ];then
		return 1
	elif check_command cmp;then
		cmp -s $1 $2
	else
		[ "$(cat $1)" = "$(cat $2)" ] && return 0 || return 1
	fi
}

add_crontab() {
	crontab -l > $TMPDIR/crontab_tmp
	grep -q "/etc/nftclash/service.sh api_config_save" $TMPDIR/crontab_tmp || echo "*/10 * * * * pgrep clash && /etc/nftclash/service.sh api_config_save" >> $TMPDIR/crontab_tmp
	crontab $TMPDIR/crontab_tmp
	rm $TMPDIR/crontab_tmp
}

get_clash_config() {
	[ -z "$3" ] && configpath="$CLASH_HOME_DIR/config.yaml" || configpath=$3
	if [ -e "$configpath" ]; then
		eval $1=$(yq e ".$2" $configpath)
	else
		echo "$configpath does not exist!!!"
	fi
}

set_config() {
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
		set_config MAC_LIST_MODE 0
		set_config LOCAL_PROXY_IPV6 0
		source $CONFIG_PATH
	fi

	[ -z "$DNS_REDIRECT" ] && DNS_REDIRECT=0
	[ -z "$PROXY_COMMON_PORT_ENABLED" ] && PROXY_COMMON_PORT_ENABLED=0
	[ -z "$PROXY_COMMON_PORT_LIST" ] && PROXY_COMMON_PORT_LIST="22,53,80,123,143,194,443,465,587,853,993,995,5222,8080,8443"
	[ -z "$BYPASS_CN_IP_ENABLED" ] && BYPASS_CN_IP_ENABLED=1
	[ -z "$BYPASS_PASS_IP_ENABLED" ] && BYPASS_PASS_IP_ENABLED=1
	[ -z "$FORCE_PROXY_IP_ENABLED" ] && FORCE_PROXY_IP_ENABLED=1
	[ -z "$MAC_LIST_MODE" ] && MAC_LIST_MODE=0
	[ -z "$LOCAL_PROXY_IPV6" ] && LOCAL_PROXY_IPV6=0

	get_clash_config tproxy_port tproxy-port
	get_clash_config redir_port redir-port
	fwmark=$redir_port
	get_clash_config clash_dns_enabled dns.enable
	get_clash_config clash_dns_listen dns.listen
	init_clash_api
}

clash_api_get(){
	if [ "$CLASH_API_AVAILABLE" = 1 ]; then
		curl -s -H "Authorization: Bearer ${clash_api_secret}" -H "Content-Type:application/json" "$1"
	else
		echo -e "${RED}Clash Api is not available!!!${NOCOLOR}"
	fi
}

clash_api_put(){
	if [ "$CLASH_API_AVAILABLE" = 1 ]; then
		curl -sS -X PUT -H "Authorization: Bearer ${clash_api_secret}" -H "Content-Type:application/json" "$1" -d "$2"
	else
		echo -e "${RED}Clash Api is not available!!!${NOCOLOR}"
	fi
}

clash_api_version() {
	clash_version=$(clash_api_get http://127.0.0.1:${clash_api_port}/version | jq -r .version)
}

clash_api_config_save() {
	clash_api_get http://127.0.0.1:${clash_api_port}/proxies | awk -F ':\\{"' '{for(i=1;i<=NF;i++) print $i}' | grep -aE '(^all|^alive)".*"Selector"' > $TMPDIR/clash_api_proxies
	compare $TMPDIR/clash_api_proxies $DIR/proxies
	[ "$?" = 0 ] && rm -f $TMPDIR/clash_api_proxies || mv -f $TMPDIR/clash_api_proxies $DIR/proxies
}

clash_api_config_restore() {
	i=1
	while [ -z "$test" -a "$i" -lt 20 ];do
		sleep 1
		test=$(curl -s http://127.0.0.1:${clash_api_port} &> /dev/null)
		i=$((i+1))
	done
	num=$(cat $DIR/proxies | wc -l)
	i=1
	while [ "$i" -le "$num" ];do
		group_name=$(awk -F ',' 'NR=="'${i}'" {print $1}' $DIR/proxies | sed 's/ /%20/g')
		now_name=$(awk -F ',' 'NR=="'${i}'" {print $2}' $DIR/proxies)
		clash_api_put http://127.0.0.1:${clash_api_port}/proxies/${group_name} "{\"name\":\"${now_name}\"}" &> /dev/null
		i=$((i+1))
	done
}

init_clash_api() {
	get_clash_config clash_api_listen external-controller
	get_clash_config clash_api_secret secret
	api_listen_ip=$(echo $clash_api_listen | cut -d ":" -f 1)
	api_listen_port=$(echo $clash_api_listen | cut -d ":" -f 2)
	if command -v curl >/dev/null 2>&1; then
		if [ -z "$api_listen_ip" ] || [ "$api_listen_port" == "0.0.0.0" ]; then
			CLASH_API_AVAILABLE=1
			clash_api_port=$api_listen_port
		else
			echo -e "${RED}You need to set the listening IP of clash api to 0.0.0.0!!!${NOCOLOR}"
			CLASH_API_AVAILABLE=0
		fi
	else
		echo -e "${RED}You need to install curl!!!${NOCOLOR}"
		CLASH_API_AVAILABLE=0
	fi
}

init_mac_list() {
	case $MAC_LIST_MODE in
	1)  # White List Mode
		[ ! -e "$DIR/ruleset/ether_white_list.txt" ] && touch "$DIR/ruleset/ether_white_list.txt"
		init_mac_white_list
		;;
	2)  # Black List Mode
		[ ! -e "$DIR/ruleset/ether_black_list.txt" ] && touch "$DIR/ruleset/ether_black_list.txt"
		init_mac_black_list
		;;
	esac
}

init_mac_white_list() {
	echo -e "${BLUE}INIT MAC_WHITE_LIST${NOCOLOR}"
	nft add set inet nftclash ether_list { type ether_addr\; } && \
	nft add rule inet nftclash prerouting ether saddr != @ether_list return
	if [ -n "$(grep -v '^$' "$DIR/ruleset/ether_white_list.txt")" ]; then
		MAC_WHITE_LIST=$(awk '{printf "%s, ",$1}' "$DIR/ruleset/ether_white_list.txt")
		nft add element inet nftclash ether_list {$MAC_WHITE_LIST}
	else
		echo "ether_white_list.txt is empty, you can edit by your self."
	fi
}

init_mac_black_list() {
	echo -e "${BLUE}INIT MAC_BLACK_LIST${NOCOLOR}"
	nft add set inet nftclash ether_list { type ether_addr\; } && \
	nft add rule inet nftclash prerouting ether saddr @ether_list return
	if [ -n "$(grep -v '^$' "$DIR/ruleset/ether_black_list.txt")" ]; then
		MAC_BLACK_LIST=$(awk '{printf "%s, ",$1}' "$DIR/ruleset/ether_black_list.txt")
		nft add element inet nftclash ether_list {$MAC_BLACK_LIST}
	else
		echo "ether_black_list.txt is empty, you can edit by your self."
	fi
}

init_force_proxy_ip() {
	echo -e "${BLUE}INIT FORCE PROXY_IP${NOCOLOR}"
	nft add set inet nftclash proxy_ip { type ipv4_addr\; flags interval\; } && \
	if [ -n "$(grep -v '^$' "$DIR/ipset/proxy_ip_list.txt")" ]; then
		PROXY_IP=$(awk '{printf "%s, ",$1}' "$DIR/ipset/proxy_ip_list.txt")
		nft add element inet nftclash proxy_ip {$PROXY_IP}
	else
		echo "proxy_ip_list.txt is empty, you can edit by your self."
	fi
}

init_force_proxy_ipv6() {
	echo -e "${BLUE}INIT FORCE PROXY_IP6${NOCOLOR}"
	nft add set inet nftclash proxy_ip6 { type ipv6_addr\; flags interval\; } && \
	if [ -n "$(grep -v '^$' "$DIR/ipset/proxy_ipv6_list.txt")" ]; then
		PROXY_IP6=$(awk '{printf "%s, ",$1}' "$DIR/ipset/proxy_ipv6_list.txt")
		nft add element inet nftclash proxy_ip6 {$PROXY_IP6}
	else
		echo "proxy_ipv6_list.txt is empty, you can edit by your self."
	fi
}

init_pass_ip_bypass() {
	echo -e "${BLUE}INIT PASS_IP BYPASS${NOCOLOR}"
	nft add set inet nftclash pass_ip { type ipv4_addr\; flags interval\; } && \
	if [ "$FORCE_PROXY_IP_ENABLED" = 1 ]; then
		nft add rule inet nftclash prerouting ip daddr @pass_ip ip daddr != @proxy_ip return
	else
		nft add rule inet nftclash prerouting ip daddr @pass_ip return
	fi
	if [ -n "$(grep -v '^$' "$DIR/ipset/pass_ip_list.txt")" ]; then
		PASS_IP=$(awk '{printf "%s, ",$1}' "$DIR/ipset/pass_ip_list.txt")
		nft add element inet nftclash pass_ip {$PASS_IP}
	else
		echo "pass_ip_list.txt is empty, you can edit by your self."
	fi
}

init_pass_ipv6_bypass() {
	echo -e "${BLUE}INIT PASS_IP6 BYPASS${NOCOLOR}"
	nft add set inet nftclash pass_ip6 { type ipv6_addr\; flags interval\; } && \
	if [ "$FORCE_PROXY_IP_ENABLED" = 1 ]; then
		nft add rule inet nftclash prerouting ip6 daddr @pass_ip6 ip6 daddr != @proxy_ip6 return
	else
		nft add rule inet nftclash prerouting ip6 daddr @pass_ip6 return
	fi
	if [ -n "$(grep -v '^$' "$DIR/ipset/pass_ipv6_list.txt")" ]; then
		PASS_IP6=$(awk '{printf "%s, ",$1}' "$DIR/ipset/pass_ipv6_list.txt")
		nft add element inet nftclash pass_ip6 {$PASS_IP6}
	else
		echo "pass_ipv6_list.txt is empty, you can edit by your self."
	fi
}

init_cn_ip_bypass() {
	if [ -n "$(grep -v '^$' "$DIR/ipset/china_ip_list.txt")" ]; then
		echo -e "${BLUE}INIT CN_IP BYPASS${NOCOLOR}"
		CN_IP=$(awk '{printf "%s, ",$1}' "$DIR/ipset/china_ip_list.txt")
		nft add set inet nftclash cn_ip { type ipv4_addr\; flags interval\; } && \
		nft add element inet nftclash cn_ip {$CN_IP} && \
		if [ "$FORCE_PROXY_IP_ENABLED" = 1 ]; then
			nft add rule inet nftclash prerouting ip daddr @cn_ip ip daddr != @proxy_ip return
		else
			nft add rule inet nftclash prerouting ip daddr @cn_ip return
		fi
	else
		echo -e "${YELLOW}china_ip_list.txt is empty!!!${NOCOLOR}"
		rm -f "$DIR/ipset/china_ip_list.txt"
	fi
}

init_cn_ipv6_bypass() {
	if [ -n "$(grep -v '^$' "$DIR/ipset/china_ipv6_list.txt")" ]; then
		echo -e "${BLUE}INIT CN_IP6 BYPASS${NOCOLOR}"
		CN_IP6=$(awk '{printf "%s, ",$1}' "$DIR/ipset/china_ipv6_list.txt")
		nft add set inet nftclash cn_ip6 { type ipv6_addr\; flags interval\; } && \
		nft add element inet nftclash cn_ip6 {$CN_IP6} && \
		if [ "$FORCE_PROXY_IP_ENABLED" = 1 ]; then
			nft add rule inet nftclash prerouting ip6 daddr @cn_ip6 ip6 daddr != @proxy_ip6 return
		else
			nft add rule inet nftclash prerouting ip6 daddr @cn_ip6 return
		fi
	else
		echo -e "${YELLOW}china_ipv6_list.txt is empty!!!${NOCOLOR}"
		rm -f "$DIR/ipset/china_ipv6_list.txt"
	fi
}

init_fw_bypass() {
	if [ "$FORCE_PROXY_IP_ENABLED" = 1 ]; then
		# IPv4 Rules
		if [ -e "$DIR/ipset/proxy_ip_list.txt" ]; then
			init_force_proxy_ip
		else
			echo -e "${YELLOW}proxy_ip_list.txt does not exist!!!${NOCOLOR}"
			echo "Creating proxy_ip_list.txt"
			touch "$DIR/ipset/proxy_ip_list.txt"
			init_force_proxy_ip
		fi
		# IPv6 Rules
		if [ -e "$DIR/ipset/proxy_ipv6_list.txt" ]; then
			init_force_proxy_ipv6
		else
			echo -e "${YELLOW}proxy_ipv6_list.txt does not exist!!!${NOCOLOR}"
			echo "Creating proxy_ipv6_list.txt"
			touch "$DIR/ipset/proxy_ipv6_list.txt"
			init_force_proxy_ipv6
		fi
	fi
	if [ "$BYPASS_PASS_IP_ENABLED" = 1 ]; then
		# IPv4 Rules
		if [ -e "$DIR/ipset/pass_ip_list.txt" ]; then
			init_pass_ip_bypass
		else
			echo -e "${YELLOW}pass_ip_list.txt does not exist!!!${NOCOLOR}"
			echo "Creating pass_ip_list.txt"
			touch "$DIR/ipset/pass_ip_list.txt"
			init_pass_ip_bypass
		fi
		# IPv6 Rules
		if [ -e "$DIR/ipset/pass_ipv6_list.txt" ]; then
			init_pass_ipv6_bypass
		else
			echo -e "${YELLOW}pass_ipv6_list.txt does not exist!!!${NOCOLOR}"
			echo "Creating pass_ipv6_list.txt"
			touch "$DIR/ipset/pass_ipv6_list.txt"
			init_pass_ipv6_bypass
		fi
	fi
	if [ "$BYPASS_CN_IP_ENABLED" = 1 ]; then
		# IPv4 Rules
		if [ -e "$DIR/ipset/china_ip_list.txt" ]; then
			init_cn_ip_bypass
		else
			echo -e "${YELLOW}china_ip_list.txt does not exist!!!${NOCOLOR}"
			wget -O "$DIR/ipset/china_ip_list.txt" "$FILES_REPO_URL/china_ip_list.txt"
			if [ "$?" = "0" ]; then
				chmod 777 "$DIR/ipset/china_ip_list.txt"
				init_cn_ip_bypass
			else
				echo -e "${RED}china_ip_list.txt download failed!!!${NOCOLOR}"
			fi
		fi
		# IPv6 Rules
		if [ -e "$DIR/ipset/china_ipv6_list.txt" ]; then
			init_cn_ipv6_bypass
		else
			echo -e "${YELLOW}china_ipv6_list.txt does not exist!!!${NOCOLOR}"
			wget -O "$DIR/ipset/china_ipv6_list.txt" "$FILES_REPO_URL/china_ipv6_list.txt"
			if [ "$?" = "0" ]; then
				chmod 777 "$DIR/ipset/china_ipv6_list.txt"
				init_cn_ipv6_bypass
			else
				echo -e "${RED}china_ipv6_list.txt download failed!!!${NOCOLOR}"
			fi
		fi
	fi
}

init_fw_dns() {
	dns_listen_ip=$(echo $clash_dns_listen | cut -d ":" -f 1)
	dns_listen_port=$(echo $clash_dns_listen | cut -d ":" -f 2)
	if [ "$clash_dns_enabled" = "true" ]; then
		if [ -z "$dns_listen_ip" ] || [ "$dns_listen_ip" == "0.0.0.0" ]; then
			echo -e "${BLUE}INIT DNS_REDIRECT${NOCOLOR}"
			nft add chain inet nftclash dns { type nat hook prerouting priority -100 \; }
			case $MAC_LIST_MODE in
			1)  # White List Mode
				nft add rule inet nftclash dns ether saddr != @ether_list return
				;;
			2)  # Black List Mode
				nft add rule inet nftclash dns ether saddr @ether_list return
				;;
			esac
			nft add rule inet nftclash dns udp dport 53 redirect to ${dns_listen_port}
			nft add rule inet nftclash dns tcp dport 53 redirect to ${dns_listen_port}
		else
			echo -e "${RED}You need to set the listening IP of clash dns to 0.0.0.0!!!${NOCOLOR}"
		fi
	else
		echo -e "${RED}Clash dns is not enabled!${NOCOLOR}"
	fi
	
}

init_fw() {
	nft add table inet nftclash
	nft flush table inet nftclash
	nft add chain inet nftclash prerouting { type filter hook prerouting priority 0 \; }

	ip rule add fwmark $fwmark table 100 2> /dev/null
	ip route add local default dev lo table 100 2> /dev/null
	ip -6 rule add fwmark $fwmark table 101 2> /dev/null
	ip -6 route add local ::/0 dev lo table 101 2> /dev/null

	RESERVED_IP="$(echo $reserve_ipv4 | sed 's/ /, /g')"
	RESERVED_IP6="$(echo $reserve_ipv6 | sed 's/ /, /g')"
	nft add rule inet nftclash prerouting ip daddr {$RESERVED_IP} return
	nft add rule inet nftclash prerouting ip6 daddr {$RESERVED_IP6} return

	init_mac_list

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

	# Local Proxy
	nft add chain inet nftclash output { type nat hook output priority -100 \; }
	nft add rule inet nftclash output meta skgid 7890 return
	nft add rule inet nftclash output ip daddr {$RESERVED_IP} return
	nft add rule inet nftclash output ip6 daddr {$RESERVED_IP6} return

	[ "$BYPASS_PASS_IP_ENABLED" = 1 ] && nft add rule inet nftclash output ip daddr @pass_ip return
	[ "$BYPASS_PASS_IP_ENABLED" = 1 ] && nft add rule inet nftclash output ip6 daddr @pass_ip6 return
	[ "$BYPASS_CN_IP_ENABLED" = 1 ] && nft add rule inet nftclash output ip daddr @cn_ip return
	[ "$BYPASS_CN_IP_ENABLED" = 1 ] && nft add rule inet nftclash output ip6 daddr @cn_ip6 return

	[ "$LOCAL_PROXY_IPV6" = 0 ] && nft add rule inet nftclash output meta nfproto ipv6 return

	nft add rule inet nftclash output meta l4proto tcp mark set $fwmark redirect to $redir_port
}

init_startup() {
	! modprobe nft_tproxy && {
		echo -e "${RED}missing nft_tproxy!!!${NOCOLOR}"
		exit 1
	}
	if ! command -v yq >/dev/null 2>&1; then
		echo -e "${RED}You need to install yq!!!${NOCOLOR}"
		exit 1
	fi
	if ! command -v jq >/dev/null 2>&1; then
		echo -e "${RED}You need to install jq!!!${NOCOLOR}"
		exit 1
	fi
	if [ -e "$CLASH_HOME_DIR/clash" ]; then
		if [ -e "$CLASH_HOME_DIR/config.yaml" ]; then
			chmod 777 -R "$DIR"
			echo -e "${BLUE}INIT STARTUP DONE!${NOCOLOR}"
		else
			echo -e "${YELLOW}Please manually move the clash config file to $CLASH_HOME_DIR/config.yaml${NOCOLOR}"
			exit 1
		fi
	else
		echo "clash file does not exist!!!"
		if [ ! -d "$CLASH_HOME_DIR" ]; then
			echo "Creating directory"
			mkdir -p "$CLASH_HOME_DIR"
			echo -e "${YELLOW}Please manually restart service!"
			exit 1
		fi
		echo -e "${YELLOW}Please manually move the clash executable file to $CLASH_HOME_DIR/clash${NOCOLOR}"
		exit 1
	fi
	if [ -z "$(id nftclash 2>/dev/null | grep 'root')" ];then
		if check_command userdel useradd groupmod; then
			userdel nftclash 2>/dev/null
			useradd nftclash -u 7890
			groupmod nftclash -g 7890
			sed -Ei s/7890:7890/0:7890/g /etc/passwd
		else
			grep -qw nftclash /etc/passwd || echo "nftclash:x:0:7890:::" >> /etc/passwd
		fi
	fi
}

init_started() {
	if [ ! -d "$DIR/ipset" ]; then
		mkdir -p "$DIR/ipset"
	fi
	if [ ! -d "$DIR/ruleset" ]; then
		mkdir -p "$DIR/ruleset"
	fi
	if [ ! -d "$TMPDIR" ]; then
		mkdir -p "$TMPDIR"
	fi
	init_config
	init_fw
	echo -e "${YELLOW}WAITTING FOR CLASH API${NOCOLOR}"
	clash_api_config_restore
	clash_api_version
	echo -e "${GREEN}API_URL: ${YELLOW}http://${host_ipv4}:${clash_api_port} ${GREEN}API_VERSION: ${YELLOW}${clash_version}${NOCOLOR}"
	add_crontab
	echo -e "${BLUE}CLASH SERVICE STARTED${NOCOLOR}"
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
	api_config_save)
		init_clash_api
		clash_api_config_save
		;;
	api_config_restore)
		init_clash_api
		clash_api_config_restore
		;;
esac
exit 0
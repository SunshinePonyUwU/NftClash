
DIR=/etc/nftclash
CLASH_HOME_DIR=$DIR/clash

CONFIG_PATH=$DIR/config.cfg

init_config() {
  # source $CONFIG_PATH
	tproxy_port=$(awk -F': ' '/tproxy-port/{print $2}' "$CLASH_HOME_DIR/config.yaml")
	redir_port=$(awk -F': ' '/redir-port/{print $2}' "$CLASH_HOME_DIR/config.yaml")
	fwmark=$redir_port
}

init_fw() {
	nft add table inet nftclash
	nft flush table inet nftclash
	nft add chain inet nftclash prerouting { type filter hook prerouting priority 0 \; }
	nft add rule inet nftclash prerouting meta l4proto { tcp, udp } mark set $fwmark tproxy to :$tproxy_port

}

init_startup() {\
	! modprobe nft_tproxy && {
		echo "missing nft_tproxy!!!"
		exit 1
	}
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
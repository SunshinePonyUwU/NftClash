
DIR=/etc/nftclash
CLASH_HOME_DIR=$DIR/clash

CONFIG_PATH=$DIR/config.cfg

init_config() {
    source $CONFIG_PATH &> /dev/null
}

init_startup() {

}

init_started() {

}

case "$1" in
    init_startup)
		init_startup
	;;
    init_started)
		init_started
	;;
esac
exit 0
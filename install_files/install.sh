if ! command -v nft >/dev/null 2>&1; then
	echo "Your system does not have nftables!!!"
	echo "Cancel the installation."
	exit 1
fi

DIR=/etc/nftclash

cp $DIR/install/service.sh $DIR/service.sh && chmod 755 $DIR/service.sh
cp $DIR/install/nftclashservice /etc/init.d/nftclash && chmod 755 /etc/init.d/nftclash && \
[ "$1" != "upgrade" ] && service nftclash enable
cp $DIR/install/hotplug /etc/hotplug.d/iface/21-nftclash && chmod 755 /etc/hotplug.d/iface/21-nftclash
[ ! -f "$DIR/version" ] && cp $DIR/install/version $DIR/version

if [ "$1" = "upgrade" ]; then
	[ -f "$DIR/config.cfg.bak" ] && rm $DIR/config.cfg.bak
	$DIR/service.sh update_config
fi

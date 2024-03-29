if ! command -v nft >/dev/null 2>&1; then
	echo "Your system does not have nftables!!!"
	echo "Cancel the installation."
	exit 1
fi

cp /etc/nftclash/install/service.sh /etc/nftclash/service.sh && chmod 755 /etc/nftclash/service.sh
cp /etc/nftclash/install/nftclashservice /etc/init.d/nftclash && chmod 755 /etc/init.d/nftclash && service nftclash enable
[ ! -f /etc/nftclash/version ] && cp /etc/nftclash/install/version /etc/nftclash/version


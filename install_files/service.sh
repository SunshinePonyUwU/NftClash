#!/bin/sh

BLUE='\033[1;34m'
YELLOW='\033[1;33m'
GREEN='\033[1;32m'
RED='\033[1;31m'
NOCOLOR='\033[0m' # No Color

LOGTAG=nftclash
LOGTAG_ECHO=NFTC

DIR=/etc/nftclash
TMPDIR=/tmp/nftclash
CLASH_HOME_DIR=$DIR/clash

CONFIG_PATH=$DIR/config.cfg
VERSION_PATH=$DIR/version

FILES_REPO_URL="https://raw.githubusercontent.com/SunshinePonyUwU/NftClashFiles/main"
REPO_URL="https://raw.githubusercontent.com/SunshinePonyUwU/NftClash/main"

# https://en.wikipedia.org/wiki/Reserved_IP_addresses
RESERVED_IPV4="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4 255.255.255.255/32"
RESERVED_IPV6="::/128 ::1/128 ::ffff:0:0/96 ::ffff:0:0:0/96 64:ff9b::/96 64:ff9b:1::/48 100::/64 2001::/32 2001:20::/28 2001:db8::/32 2002::/16 3fff::/20 5f00::/16 fc00::/7 fe80::/10 ff00::/8"
HOST_IPV4=$(ubus call network.interface.lan status 2>&1 | jq -r '.["ipv4-address"][0].address')
HOST_IPV6=$(ubus call network.interface.lan status 2>&1 | jq -r '.["ipv6-address"][0].address')
[ "$HOST_IPV6" = "null" ] && HOST_IPV6=$(ubus call network.interface.lan status 2>&1 | jq -r '.["ipv6-prefix-assignment"][0].["local-address"].address')

CLASH_API_READY=0

log() {
  local level=$1
  local msg=$(echo -e "$2" | sed -E 's/\x1B\[[0-9;]*[a-zA-Z]//g')
  local priority="daemon.notice"
  local level_text="NOTICE"

  case $level in
    debug)
      priority="daemon.debug"
      level_text="DEBUG"
      ;;
    info) 
      priority="daemon.info"
      level_text="INFO"
      ;;
    warn) 
      priority="daemon.warn"
      level_text="WARN"
      ;;
    err)  
      priority="daemon.err"
      level_text="ERROR"
      ;;
  esac

  logger -t "$LOGTAG" -p "$priority" "[$level_text] $msg"
}

log_info() {
    local msg=$1

    log info "$msg"
    echo -e "[${GREEN}$LOGTAG_ECHO${NOCOLOR}][${BLUE}INFO${NOCOLOR}] ${BLUE}$msg${NOCOLOR}"
}

log_warn() {
    local msg=$1

    log warn "$msg"
    echo -e "[${GREEN}$LOGTAG_ECHO${NOCOLOR}][${YELLOW}WARN${NOCOLOR}] ${YELLOW}$msg${NOCOLOR}" >&2
}

log_error() {
    local msg=$1

    log err "$msg"
    echo -e "[${GREEN}$LOGTAG_ECHO${NOCOLOR}][${RED}ERROR${NOCOLOR}] ${RED}$msg${NOCOLOR}" >&2
}

check_command() {
  command -v sh &>/dev/null && command -v $1 &>/dev/null || type $1 &>/dev/null
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
  local arg1=$1

  # DEFAULT HIDDEN CONFIGS
  DNS_REDIRECT=0
  # DEFAULT CONFIGS
  BYPASS_SOURCE_PORT_ENABLED=0
  BYPASS_SOURCE_PORT_LIST="0-1023"
  BYPASS_DEST_PORT_ENABLED=1
  BYPASS_DEST_PORT_LIST="123,3478-3479"
  PROXY_COMMON_PORT_ENABLED=0
  PROXY_COMMON_PORT_LIST="22,53,80,123,143,194,443,465,587,853,993,995,5222,8080,8443"
  PROXY_COMMON_PORT_LOCAL_ENABLED=0
  PROXY_COMMON_PORT_MAC_LIST_ENABLED=0
  BYPASS_CN_IP_ENABLED=1
  BYPASS_PASS_IP_ENABLED=1
  FORCE_PROXY_IP_ENABLED=1
  SOURCE_IP_LIST_MODE=0
  MAC_LIST_MODE=0
  LOCAL_PROXY_IPV6=0
  LOCAL_PROXY_BYPASS_53=0
  BYPASS_53_TCP=0
  BYPASS_53_UDP=0
  REJECT_QUIC=0
  ICMP_REDIRECT=0
  LOOPBACK_CHECKS_ENABLED=1
  INIT_CHECKS_ENABLED=1
  CONN_CHECKS_ENABLED=1
  CONN_CHECKS_INTERVAL=300
  CONN_CHECKS_RETRY_INTERVAL=8
  CONN_CHECKS_MAX_FAILURES=5
  CONN_CHECKS_MIN_SUCCESSES=5
  CONN_CHECKS_URL=http://cp.cloudflare.com/
  CLASH_CONFIG_UPDATE_ENABLED=0
  CLASH_CONFIG_UPDATE_URL=""
  CLASH_CONFIG_UPDATE_UA=""
  CLASH_LOG_STDOUT=0

  if [ "$arg1" = "update" ]; then
    source $CONFIG_PATH
    mv "$CONFIG_PATH" "$CONFIG_PATH.bak" || return 1
  fi

  if [ -e "$CONFIG_PATH" ]; then
    source $CONFIG_PATH
  else
    log_info "generating config"
    touch $CONFIG_PATH
    set_config FILES_REPO_URL $FILES_REPO_URL
    set_config REPO_URL $REPO_URL
    set_config BYPASS_SOURCE_PORT_ENABLED $BYPASS_SOURCE_PORT_ENABLED
    set_config BYPASS_SOURCE_PORT_LIST $BYPASS_SOURCE_PORT_LIST
    set_config BYPASS_DEST_PORT_ENABLED $BYPASS_DEST_PORT_ENABLED
    set_config BYPASS_DEST_PORT_LIST $BYPASS_DEST_PORT_LIST
    set_config PROXY_COMMON_PORT_ENABLED $PROXY_COMMON_PORT_ENABLED
    set_config PROXY_COMMON_PORT_LIST $PROXY_COMMON_PORT_LIST
    set_config PROXY_COMMON_PORT_LOCAL_ENABLED $PROXY_COMMON_PORT_LOCAL_ENABLED
    set_config PROXY_COMMON_PORT_MAC_LIST_ENABLED $PROXY_COMMON_PORT_MAC_LIST_ENABLED
    set_config BYPASS_CN_IP_ENABLED $BYPASS_CN_IP_ENABLED
    set_config BYPASS_PASS_IP_ENABLED $BYPASS_PASS_IP_ENABLED
    set_config FORCE_PROXY_IP_ENABLED $FORCE_PROXY_IP_ENABLED
    set_config SOURCE_IP_LIST_MODE $SOURCE_IP_LIST_MODE
    set_config MAC_LIST_MODE $MAC_LIST_MODE
    set_config LOCAL_PROXY_IPV6 $LOCAL_PROXY_IPV6
    set_config LOCAL_PROXY_BYPASS_53 $LOCAL_PROXY_BYPASS_53
    set_config BYPASS_53_TCP $BYPASS_53_TCP
    set_config BYPASS_53_UDP $BYPASS_53_UDP
    set_config REJECT_QUIC $REJECT_QUIC
    set_config ICMP_REDIRECT $ICMP_REDIRECT
    set_config INIT_CHECKS_ENABLED $INIT_CHECKS_ENABLED
    set_config CONN_CHECKS_ENABLED $CONN_CHECKS_ENABLED
    set_config CONN_CHECKS_INTERVAL $CONN_CHECKS_INTERVAL
    set_config CONN_CHECKS_RETRY_INTERVAL $CONN_CHECKS_RETRY_INTERVAL
    set_config CONN_CHECKS_MAX_FAILURES $CONN_CHECKS_MAX_FAILURES
    set_config CONN_CHECKS_MIN_SUCCESSES $CONN_CHECKS_MIN_SUCCESSES
    set_config CONN_CHECKS_URL $CONN_CHECKS_URL
    set_config CLASH_CONFIG_UPDATE_ENABLED $CLASH_CONFIG_UPDATE_ENABLED
    set_config CLASH_CONFIG_UPDATE_URL $CLASH_CONFIG_UPDATE_URL
    set_config CLASH_CONFIG_UPDATE_UA $CLASH_CONFIG_UPDATE_UA
    set_config CLASH_LOG_STDOUT $CLASH_LOG_STDOUT
  fi

  get_clash_config tproxy_port tproxy-port
  get_clash_config redir_port redir-port
  get_clash_config socks_port socks-port
  [ "$socks_port" = "null" ] && get_clash_config socks_port mixed-port
  [ "$socks_port" = "null" ] && {
    CONN_CHECKS_ENABLED=0
    log_error "Connection checks disabled! socks-port or mixed-port is not defined."
  }
  fwmark=$redir_port
  get_clash_config clash_dns_enabled dns.enable
  get_clash_config clash_dns_listen dns.listen
}

init_clash_api() {
  get_clash_config CLASH_API_LISTEN external-controller
  get_clash_config CLASH_API_SECRET secret
  API_LISTEN_IP=$(echo $CLASH_API_LISTEN | cut -d ":" -f 1)
  API_LISTEN_PORT=$(echo $CLASH_API_LISTEN | cut -d ":" -f 2)
  if command -v curl >/dev/null 2>&1; then
    if [ -n "$API_LISTEN_PORT" ] && { [ -z "$API_LISTEN_IP" ] || [ "$API_LISTEN_IP" = "0.0.0.0" ]; }; then
      CLASH_API_PORT=$API_LISTEN_PORT
      CLASH_API_AVAILABLE=1
    else
      log_warn "You need to set the listening IP of clash api to 0.0.0.0!!!"
      CLASH_API_AVAILABLE=0
    fi
  else
    log_warn "You need to install curl!!!"
    CLASH_API_AVAILABLE=0
  fi
}

loopback_check() {
  local wan_zone_section=$(uci show firewall | grep -E "(@zone\[[0-9]+\]|@zone\[[a-zA-Z0-9_]+\])\.name='wan'" | cut -d'=' -f1 | cut -d'.' -f1-2)
  [ -z "$wan_zone_section" ] && {
    log_error "firewall zone 'wan' is net exist!!!"
    return 1
  }
  local wan_network_list=$(uci get "${wan_zone_section}.network" 2>/dev/null)
  [ -z "$wan_network_list" ] && {
    log_error "firewall zone 'wan' does not contain any interfaces!!!"
    return 1
  }

  local ipv4_addr_list=""
  local ipv6_addr_list=""
  local ipv6_prefix_list=""

  nft list table inet nftclash&> /dev/null && {
    for interface in $wan_network_list; do
      local interface_status=$(ubus call "network.interface.${interface}" status 2>&1)
      local ipv4_addrs=$(echo $interface_status | jq -r '.["ipv4-address"]?[]? | "\(.address)/\(.mask)"')
      local ipv6_addrs=$(echo $interface_status | jq -r '.["ipv6-address"]?[]? | "\(.address)/\(.mask)" | select(startswith("fe80::") | not)')
      local ipv6_prefx=$(echo $interface_status | jq -r '.["ipv6-prefix"]?[]? | "\(.address)/\(.mask)"')

      # IPv4 Address
      for ipv4_address in $ipv4_addrs; do
        if [ -n "$ipv4_address" ]; then
          if [ -n "$ipv4_addr_list" ]; then
              ipv4_addr_list="${ipv4_addr_list},${ipv4_address}"
          else
              ipv4_addr_list="${ipv4_address}"
          fi
        fi
      done

      # IPv6 Address
      for ipv6_address in $ipv6_addrs; do
        if [ -n "$ipv6_address" ]; then
          if [ -n "$ipv6_addr_list" ]; then
              ipv6_addr_list="${ipv6_addr_list},${ipv6_address}"
          else
              ipv6_addr_list="${ipv6_address}"
          fi
        fi
      done

      # IPv6 Prefix
      for ipv6_prefix in $ipv6_prefx; do
        if [ -n "$ipv6_prefix" ]; then
          if [ -n "$ipv6_prefix_list" ]; then
              ipv6_prefix_list="${ipv6_prefix_list},${ipv6_prefix}"
          else
              ipv6_prefix_list="${ipv6_prefix}"
          fi
        fi
      done
    done
    log_info "loopback_check ipv4_addr_list = $ipv4_addr_list"
    log_info "loopback_check ipv6_addr_list = $ipv6_addr_list"
    log_info "loopback_check ipv6_prefix_list = $ipv6_prefix_list"
    nft flush set inet nftclash loopback_ipv4_list
    [ -n "$ipv4_addr_list" ] && nft add element inet nftclash loopback_ipv4_list {$ipv4_addr_list}
    nft flush set inet nftclash loopback_ipv6_list
    [ -n "$ipv6_addr_list" ] && nft add element inet nftclash loopback_ipv6_list {$ipv6_addr_list}
    [ -n "$ipv6_prefix_list" ] && nft add element inet nftclash loopback_ipv6_list {$ipv6_prefix_list}
  }
}

connection_check() {
  [ "$INIT_CHECKS_ENABLED" = 0 ] && return 0
  [ "$CONN_CHECKS_ENABLED" = 1 ] && {
    local CHECK_FAILURE=0
    local CHECK_FAILURE_COUNT=0
    local CHECK_SUCCESS=1
    local CHECK_SUCCESS_COUNT=0
    local RETRYING=0
    while true; do
      local is_tproxy_chain_initialized=$(nft -j list chain inet nftclash transparent_proxy 2> /dev/null | jq -e '.nftables | map(select(.rule)) | length != 0')

      if [ "$CLASH_API_READY" = 1 ]; then
        curl -x "socks5://127.0.0.1:$socks_port" -s "$CONN_CHECKS_URL"&> /dev/null
        if [ $? -eq 0 ]; then
          CHECK_FAILURE_COUNT=0
          [ "$is_tproxy_chain_initialized" = "false" ] && {
            CHECK_SUCCESS_COUNT=$(( CHECK_SUCCESS_COUNT + 1 ))
            if [ "$CHECK_SUCCESS_COUNT" -ge "$CONN_CHECKS_MIN_SUCCESSES" ]; then
              init_tproxy
              log_info "socks5 test success, init tproxy. (x$CHECK_SUCCESS_COUNT)"
              CHECK_FAILURE=0
              CHECK_SUCCESS=1
              RETRYING=0
            else
              log_info "socks5 test success. (x$CHECK_SUCCESS_COUNT)"
              RETRYING=1
            fi
          }
        else
          CHECK_SUCCESS_COUNT=0
          [ "$is_tproxy_chain_initialized" = "true" ] && {
            CHECK_FAILURE_COUNT=$(( CHECK_FAILURE_COUNT + 1 ))
            if [ "$CHECK_FAILURE_COUNT" -ge "$CONN_CHECKS_MAX_FAILURES" ]; then
              flush_tproxy
              log_warn "socks5 test failure, flush tproxy. (x$CHECK_FAILURE_COUNT)"
              CHECK_FAILURE=1
              CHECK_SUCCESS=0
              RETRYING=1
            else
              log_warn "socks5 test failure. (x$CHECK_FAILURE_COUNT)"
              RETRYING=1
            fi
          }
        fi

        [ "$RETRYING" = 1 ] && sleep "$CONN_CHECKS_RETRY_INTERVAL"
        [ "$RETRYING" = 0 ] && sleep "$CONN_CHECKS_INTERVAL"
      else
        sleep 1
      fi
    done
  }
}

get_conf() {
  conf_name="$1"
  [ -z "$conf_name" ] && log_error "missing argument." && return 1
  eval "conf_value=\"\${$conf_name}\""
  if [ -n "$conf_value" ]; then
    log_info "${YELLOW}$conf_name${NOCOLOR}=${GREEN}$conf_value${NOCOLOR}"
  else
    log_error "$conf_name is not defined."
  fi
}

set_conf() {
  conf_name="$1"
  conf_value_new="$2"
  extra_argument="$3"
  [ -z "$conf_name" ] && log_error "missing argument." && return 1
  eval "conf_value=\"\${$conf_name}\""
  if [ -n "$conf_value" ] || [ "$extra_argument" = "force" ]; then
    if [ -n "$conf_value_new" ]; then
      set_config $conf_name $conf_value_new && \
      log_info "SET CONFIG $conf_name=$conf_value_new DONE!"
    else
      log_error "new value is not defined."
    fi
  else
    log_error "$conf_name is not defined."
  fi
}

# LINK, PATH, UA
download_file() {
  local link=$1
  local path=$2
  local ua="nftclash-download"
  local path_exist=0
  [ -n "$3" ] && ua=$3
  [ -f "$path" ] && path_exist=1
  [ "$path_exist" = 1 ] && mv "$path" "$path.dl_bak"
  log_info "downloading $link"
  curl -fL -o "$path" -A "$ua" --progress-bar "$link"
  if [ $? -eq 0 ]; then
    [ "$path_exist" = 1 ] && rm -f "$path.dl_bak"
    return 0
  else
    log_error "download failure!!!"
    [ "$path_exist" = 1 ] && {
      rm -f "$path"
      mv "$path.dl_bak" "$path"
    }
    return 1
  fi
  return $?
}

fetch_files_repo(){
  curl -s "$FILES_REPO_URL$1"
}

fetch_repo(){
  curl -s "$REPO_URL$1"
}

clash_api_fetch() {
  local fetch_method=$1
  local fetch_path=$2
  local fetch_data=$3
  [ -z "$fetch_method" ] && fetch_method="GET"
  log_info "clash_api_fetch $fetch_method $fetch_path $fetch_data"
  if [ "$CLASH_API_AVAILABLE" = 1 ]; then
    curl -s -X "$fetch_method" -H "Authorization: Bearer ${CLASH_API_SECRET}" -H "Content-Type:application/json" "http://127.0.0.1:${CLASH_API_PORT}/${fetch_path}" -d "$fetch_data"
    if [ "$?" = 0 ]; then
      return 0
    else
      log_warn "clash_api_fetch $fetch_path failed!!!"
      return 1
    fi
  else
    log_warn "Clash Api is not available!!!"
    return 1
  fi
}

silent_update_china_iplist() {
  local download_code_china_ipv4_list=2
  local download_code_china_ipv6_list=2
  if [ -e "$VERSION_PATH" ]; then
    source $VERSION_PATH
  else
    log_error "version file is missing!!!"
    return 1
  fi
  update_data=$(fetch_files_repo "/update.json")
  [ -z "$update_data" ] && {
    log_error "UPDATE CHECK FAILED!!!"
    return 1
  }
  latest_china_iplist_version=$(echo "$update_data" | jq .china_ip_version)
  if [ "$BYPASS_CN_IP_ENABLED" = 1 ]; then
    if [ -n "$VERSION_CHINA_IPLIST" ]; then
      if [ ! $VERSION_CHINA_IPLIST -eq $latest_china_iplist_version ]; then
        download_file "$FILES_REPO_URL/china_ip_list.txt" "$DIR/ipset/china_ip_list.txt"
        download_code_china_ipv4_list=$?
        download_file "$FILES_REPO_URL/china_ipv6_list.txt" "$DIR/ipset/china_ipv6_list.txt"
        download_code_china_ipv6_list=$?
        [ "$download_code_china_ipv4_list" = 0 ] &&\
        [ "$download_code_china_ipv6_list" = 0 ] && {
          chmod 777 "$DIR/ipset/china_ip_list.txt"
          chmod 777 "$DIR/ipset/china_ipv6_list.txt"
          set_config VERSION_CHINA_IPLIST "$latest_china_iplist_version" "$VERSION_PATH"
          nft list set inet nftclash cn_ip &> /dev/null && {
            nft flush set inet nftclash cn_ip
            nft add element inet nftclash cn_ip {$(awk '{printf "%s, ",$1}' "$DIR/ipset/china_ip_list.txt")}
          }
          nft list set inet nftclash cn_ip6 &> /dev/null && {
            nft flush set inet nftclash cn_ip6
            nft add element inet nftclash cn_ip6 {$(awk '{printf "%s, ",$1}' "$DIR/ipset/china_ipv6_list.txt")}
          }
          log_info "UPDATE CHINA IP DONE!!! VER: $latest_china_iplist_version"
        }
      fi
    fi
  fi
}

reload_clash_config() {
  local arg1=$1
  clash_api_fetch PUT "configs?force=true" "{\"path\":\"\",\"payload\":\"\"}" && \
  [ "$arg1" = "force" ] && clash_api_fetch DELETE connections
  return 0
}

silent_update_clash_config() {
  if [ "$CLASH_CONFIG_UPDATE_ENABLED" = 1 ] && [ "$CLASH_CONFIG_UPDATE_URL" != "" ]; then
    [ -z "$CLASH_CONFIG_UPDATE_UA" ] && download_ua="nftclash-download/config-update-silent" || download_ua=$CLASH_CONFIG_UPDATE_UA
    download_file "$CLASH_CONFIG_UPDATE_URL" "$CLASH_HOME_DIR/config.yaml" "$download_ua"
    if [ $? -eq 0 ]; then
      chmod 777 "$CLASH_HOME_DIR/config.yaml"
      clash_api_fetch PUT "configs?force=true" "{\"path\":\"\",\"payload\":\"\"}" &> /dev/null && {
        log_info "UPDATE CLASH CONFIG DONE!!!"
      }
    else
      log_warn "UPDATE CLASH CONFIG FAILED!!!"
    fi
  fi
}

update_clash_config() {
  if [ "$CLASH_CONFIG_UPDATE_ENABLED" = 1 ] && [ "$CLASH_CONFIG_UPDATE_URL" != "" ]; then
    log_info "UPDATE CLASH CONFIG"
    [ -z "$CLASH_CONFIG_UPDATE_UA" ] && download_ua="nftclash-download/config-update" || download_ua=$CLASH_CONFIG_UPDATE_UA
    download_file "$CLASH_CONFIG_UPDATE_URL" "$CLASH_HOME_DIR/config.yaml" "$download_ua"
    if [ $? -eq 0 ]; then
      chmod 777 "$CLASH_HOME_DIR/config.yaml"
      log_info "RELOAD CONFIG"
      clash_api_fetch PUT "configs?force=true" "{\"path\":\"\",\"payload\":\"\"}" && {
        log_info "UPDATE CLASH CONFIG DONE!!!"
      }
    else
      log_warn "UPDATE CLASH CONFIG FAILED!!!"
    fi
  else
    log_error "please configure CLASH_CONFIG_UPDATE_ENABLED and CLASH_CONFIG_UPDATE_URL"
  fi
}

check_update() {
  local arg1=$1
  # When the code is 0 means the download was successful.
  local download_code_china_ipv4_list=2
  local download_code_china_ipv6_list=2
  local download_code_hotplug=2
  local download_code_install_sh=2
  local download_code_nftclashservice=2
  local download_code_service_sh=2
  local download_code_version=2
  if [ "$arg1" = "force" ]; then
    VERSION_SERVICE=0
    VERSION_CHINA_IPLIST=0
  elif [ "$arg1" = "force-service" ]; then
    VERSION_SERVICE=0
  elif [ "$arg1" = "force-china-iplist" ]; then
    VERSION_CHINA_IPLIST=0
  else
    if [ -e "$VERSION_PATH" ]; then
      VERSION_SERVICE=0
      VERSION_CHINA_IPLIST=0
      source $VERSION_PATH
      [ -z "$VERSION_SERVICE" ] && {
        log_error "version info is missing!!!"
        return 1
      }
    else
      log_error "version file is missing!!!"
      return 1
    fi
  fi
  
  update_data=$(fetch_files_repo "/update.json")
  [ -z "$update_data" ] && {
    log_error "UPDATE CHECK FAILED!!!"
    return 1
  }
  latest_service_version=$(echo "$update_data" | jq .service_version)
  latest_china_iplist_version=$(echo "$update_data" | jq .china_ip_version)
  if [ -n "$VERSION_SERVICE" ]; then
    if [ $VERSION_SERVICE -eq $latest_service_version ]; then
      log_info "${GREEN}SERVICE SCRIPT IS UP TO DATE${NOCOLOR}"
    else
      log_info "${YELLOW}SERVICE SCRIPT HAVE AN UPDATE${NOCOLOR}"
      read -p "Do you want update right now? [y|N]: " ReadLine
      case "$ReadLine" in
        "y")
          download_file "$REPO_URL/install_files/hotplug" "$DIR/install/hotplug"
          download_code_hotplug=$?
          download_file "$REPO_URL/install_files/install.sh" "$DIR/install/install.sh"
          download_code_install_sh=$?
          download_file "$REPO_URL/install_files/nftclashservice" "$DIR/install/nftclashservice"
          download_code_nftclashservice=$?
          download_file "$REPO_URL/install_files/service.sh" "$DIR/install/service.sh"
          download_code_service_sh=$?
          download_file "$REPO_URL/install_files/version" "$DIR/install/version"
          download_code_version=$?
          [ "$download_code_hotplug" = 0 ] &&\
          [ "$download_code_install_sh" = 0 ] &&\
          [ "$download_code_nftclashservice" = 0 ] &&\
          [ "$download_code_service_sh" = 0 ] &&\
          [ "$download_code_version" = 0 ] && {
            chmod 777 -R "$DIR/install/"
            $DIR/install/install.sh upgrade
            local VERSION_SERVICE=0
            source "$DIR/install/version"
            set_config VERSION_SERVICE "$VERSION_SERVICE" "$VERSION_PATH"
          }
          ;;
      esac
    fi
  fi
  if [ "$BYPASS_CN_IP_ENABLED" = 1 ]; then
    if [ -n "$VERSION_CHINA_IPLIST" ]; then
      if [ $VERSION_CHINA_IPLIST -eq $latest_china_iplist_version ]; then
        log_info "${GREEN}CHINA IP LIST IS UP TO DATE${NOCOLOR}"
      else
        log_info "${YELLOW}CHINA IP LIST HAVE AN UPDATE${NOCOLOR}"
        read -p "Do you want update right now? [y|N]: " ReadLine
        case "$ReadLine" in
          "y")
            download_file "$FILES_REPO_URL/china_ip_list.txt" "$DIR/ipset/china_ip_list.txt"
            download_code_china_ipv4_list=$?
            download_file "$FILES_REPO_URL/china_ipv6_list.txt" "$DIR/ipset/china_ipv6_list.txt"
            download_code_china_ipv6_list=$?
            chmod 777 "$DIR/ipset/china_ip_list.txt"
            chmod 777 "$DIR/ipset/china_ipv6_list.txt"
            [ "$download_code_china_ipv4_list" = 0 ] &&\
            [ "$download_code_china_ipv6_list" = 0 ] && {
              set_config VERSION_CHINA_IPLIST "$latest_china_iplist_version" "$VERSION_PATH"
              nft list set inet nftclash cn_ip &> /dev/null && {
                log_info "UPDATE CHINA IP SET"
                nft flush set inet nftclash cn_ip
                nft add element inet nftclash cn_ip {$(awk '{printf "%s, ",$1}' "$DIR/ipset/china_ip_list.txt")}
              }
              nft list set inet nftclash cn_ip6 &> /dev/null && {
                log_info "UPDATE CHINA IPV6 SET"
                nft flush set inet nftclash cn_ip6
                nft add element inet nftclash cn_ip6 {$(awk '{printf "%s, ",$1}' "$DIR/ipset/china_ipv6_list.txt")}
              }
            }
            ;;
        esac
      fi
    fi
  fi
}

download_china_ip_list() {
  test=1
  while [ -z "$can_reach_files_repo" -a "$test" -lt 30 ];do
    sleep 1
    can_reach_files_repo=$(curl -s $FILES_REPO_URL)
    test=$((test+1))
  done
  log_warn "china_ip_list.txt does not exist!!!"
  download_file "$FILES_REPO_URL/china_ip_list.txt" "$DIR/ipset/china_ip_list.txt"
  if [ "$?" = "0" ]; then
    update_china_iplist_version
    chmod 777 "$DIR/ipset/china_ip_list.txt"
    init_cn_ip_bypass
  else
    log_error "china_ip_list.txt download failed!!!"
  fi
}

download_china_ipv6_list() {
  test=1
  while [ -z "$can_reach_files_repo" -a "$test" -lt 30 ];do
    sleep 1
    can_reach_files_repo=$(curl -s $FILES_REPO_URL)
    test=$((test+1))
  done
  log_warn "china_ipv6_list.txt does not exist!!!"
  download_file "$FILES_REPO_URL/china_ipv6_list.txt" "$DIR/ipset/china_ipv6_list.txt"
  if [ "$?" = "0" ]; then
    update_china_iplist_version
    chmod 777 "$DIR/ipset/china_ipv6_list.txt"
    init_cn_ipv6_bypass
  else
    log_error "china_ipv6_list.txt download failed!!!"
  fi
}

update_china_iplist_version() {
  update_data=$(fetch_files_repo "/update.json")
  [ -z "$update_data" ] && {
    log_error "UPDATE CHECK FAILED!!!"
  }
  latest_china_iplist_version=$(echo "$update_data" | jq .china_ip_version)
  set_config VERSION_CHINA_IPLIST "$latest_china_iplist_version" "$VERSION_PATH"
}

process_proxy_fw_rules() {
  file="$1"
  rule="$2"
  for line in $(cat $file); do
    line=$(echo "$line" | tr -d '\r' | tr -d '\n')
    ipv="ip"
    ipv6_prefix=0
    if echo "$line" | grep -q "\["; then
      ipv="ip6"
      ip=$(echo "$line" | sed -e 's/^\[\(.*\)\]:.*/\1/')
      rest=$(echo "$line" | sed -e 's/^\[.*\]:\([0-9]*\)#\(.*\)/\1#\2/')
      if echo "$ip" | grep -q "/::"; then
        ipv6_prefix=1
      fi
    else
      ip=$(echo "$line" | sed -e 's/^\([^:]*\):.*/\1/')
      rest=$(echo "$line" | sed -e 's/^[^:]*:\([0-9]*\)#\(.*\)/\1#\2/')
    fi
    port=$(echo "$rest" | cut -d'#' -f1)
    protocol=$(echo "$rest" | cut -d'#' -f2 | awk '{print tolower($0)}')

    if [ "$ipv6_prefix" = 1 ]; then
      ip_part1=$(echo "$ip" | cut -d'/' -f1)
      ip_part2=$(echo "$ip" | cut -d'/' -f2)
      ip="& $ip_part2 == $ip_part1"
    fi

    [ "$rule" = "src" ] && nft add rule inet nftclash force_proxy $ipv saddr $ip $protocol sport $port jump transparent_proxy
    [ "$rule" = "dest" ] && nft add rule inet nftclash force_proxy $ipv daddr $ip $protocol dport $port jump transparent_proxy
  done
}

init_proxy_list() {
  log_info "INIT PROXY_LIST"
  [ ! -e "$DIR/ruleset/src_ipv4_proxy_list.txt" ] && touch "$DIR/ruleset/src_ipv4_proxy_list.txt"
  [ ! -e "$DIR/ruleset/src_ipv6_proxy_list.txt" ] && touch "$DIR/ruleset/src_ipv6_proxy_list.txt"
  process_proxy_fw_rules "$DIR/ruleset/src_ipv4_proxy_list.txt" "src"
  process_proxy_fw_rules "$DIR/ruleset/src_ipv6_proxy_list.txt" "src"
  [ ! -e "$DIR/ruleset/dest_ipv4_proxy_list.txt" ] && touch "$DIR/ruleset/dest_ipv4_proxy_list.txt"
  [ ! -e "$DIR/ruleset/dest_ipv6_proxy_list.txt" ] && touch "$DIR/ruleset/dest_ipv6_proxy_list.txt"
  process_proxy_fw_rules "$DIR/ruleset/dest_ipv4_proxy_list.txt" "dest"
  process_proxy_fw_rules "$DIR/ruleset/dest_ipv6_proxy_list.txt" "dest"
}

process_bypass_fw_rules() {
  file="$1"
  rule="$2"
  for line in $(cat $file); do
    line=$(echo "$line" | tr -d '\r' | tr -d '\n')
    ipv="ip"
    ipv6_prefix=0
    if echo "$line" | grep -q "\["; then
      ipv="ip6"
      ip=$(echo "$line" | sed -e 's/^\[\(.*\)\]:.*/\1/')
      rest=$(echo "$line" | sed -e 's/^\[.*\]:\([0-9]*\)#\(.*\)/\1#\2/')
      if echo "$ip" | grep -q "/::"; then
        ipv6_prefix=1
      fi
    else
      ip=$(echo "$line" | sed -e 's/^\([^:]*\):.*/\1/')
      rest=$(echo "$line" | sed -e 's/^[^:]*:\([0-9]*\)#\(.*\)/\1#\2/')
    fi
    port=$(echo "$rest" | cut -d'#' -f1)
    protocol=$(echo "$rest" | cut -d'#' -f2 | awk '{print tolower($0)}')

    if [ "$ipv6_prefix" = 1 ]; then
      ip_part1=$(echo "$ip" | cut -d'/' -f1)
      ip_part2=$(echo "$ip" | cut -d'/' -f2)
      ip="& $ip_part2 == $ip_part1"
    fi

    [ "$rule" = "src" ] && nft add rule inet nftclash bypass_proxy $ipv saddr $ip $protocol sport $port accept
    [ "$rule" = "dest" ] && nft add rule inet nftclash bypass_proxy $ipv daddr $ip $protocol dport $port accept
  done
}

init_bypass_list() {
  log_info "INIT BYPASS_LIST"
  [ ! -e "$DIR/ruleset/src_ipv4_bypass_list.txt" ] && touch "$DIR/ruleset/src_ipv4_bypass_list.txt"
  [ ! -e "$DIR/ruleset/src_ipv6_bypass_list.txt" ] && touch "$DIR/ruleset/src_ipv6_bypass_list.txt"
  process_bypass_fw_rules "$DIR/ruleset/src_ipv4_bypass_list.txt" "src"
  process_bypass_fw_rules "$DIR/ruleset/src_ipv6_bypass_list.txt" "src"
  [ ! -e "$DIR/ruleset/dest_ipv4_bypass_list.txt" ] && touch "$DIR/ruleset/dest_ipv4_bypass_list.txt"
  [ ! -e "$DIR/ruleset/dest_ipv6_bypass_list.txt" ] && touch "$DIR/ruleset/dest_ipv6_bypass_list.txt"
  process_bypass_fw_rules "$DIR/ruleset/dest_ipv4_bypass_list.txt" "dest"
  process_bypass_fw_rules "$DIR/ruleset/dest_ipv6_bypass_list.txt" "dest"
}

init_source_ip_list() {
  case $SOURCE_IP_LIST_MODE in
  1)  # White List Mode
    [ ! -e "$DIR/ruleset/source_ipv4_white_list.txt" ] && touch "$DIR/ruleset/source_ipv4_white_list.txt"
    [ ! -e "$DIR/ruleset/source_ipv6_white_list.txt" ] && touch "$DIR/ruleset/source_ipv6_white_list.txt"
    init_source_ip_white_list
    ;;
  2)  # Black List Mode
    [ ! -e "$DIR/ruleset/source_ipv4_black_list.txt" ] && touch "$DIR/ruleset/source_ipv4_black_list.txt"
    [ ! -e "$DIR/ruleset/source_ipv6_black_list.txt" ] && touch "$DIR/ruleset/source_ipv6_black_list.txt"
    init_source_ip_black_list
    ;;
  esac
}

init_source_ip_white_list() {
  log_info "INIT SOURCE_IP_WHITE_LIST"
  nft add set inet nftclash source_ipv4_list { type ipv4_addr\; flags interval\; } && \
  nft add set inet nftclash source_ipv6_list { type ipv6_addr\; flags interval\; } && \
  nft add rule inet nftclash prerouting ip saddr != @source_ipv4_list return && \
  nft add rule inet nftclash prerouting_nat ip saddr != @source_ipv4_list return && \
  nft add rule inet nftclash prerouting ip6 saddr != @source_ipv6_list return && \
  nft add rule inet nftclash prerouting_nat ip6 saddr != @source_ipv6_list return && \
  {
    if [ -n "$(grep -v '^$' "$DIR/ruleset/source_ipv4_white_list.txt")" ]; then
      SOURCE_IPV4_WHITE_LIST=$(awk '{printf "%s, ",$1}' "$DIR/ruleset/source_ipv4_white_list.txt")
      nft add element inet nftclash source_ipv4_list {$SOURCE_IPV4_WHITE_LIST}
    fi
    if [ -n "$(grep -v '^$' "$DIR/ruleset/source_ipv6_white_list.txt")" ]; then
      SOURCE_IPV6_WHITE_LIST=$(awk '{printf "%s, ",$1}' "$DIR/ruleset/source_ipv6_white_list.txt")
      nft add element inet nftclash source_ipv6_list {$SOURCE_IPV6_WHITE_LIST}
    fi
  }
}

init_source_ip_black_list() {
  log_info "INIT SOURCE_IP_BLACK_LIST"
  nft add set inet nftclash source_ipv4_list { type ipv4_addr\; flags interval\; } && \
  nft add set inet nftclash source_ipv6_list { type ipv6_addr\; flags interval\; } && \
  nft add rule inet nftclash prerouting ip saddr @source_ipv4_list return && \
  nft add rule inet nftclash prerouting_nat ip saddr @source_ipv4_list return && \
  nft add rule inet nftclash prerouting ip6 saddr @source_ipv6_list return && \
  nft add rule inet nftclash prerouting_nat ip6 saddr @source_ipv6_list return && \
  {
    if [ -n "$(grep -v '^$' "$DIR/ruleset/source_ipv4_black_list.txt")" ]; then
      SOURCE_IPV4_BLACK_LIST=$(awk '{printf "%s, ",$1}' "$DIR/ruleset/source_ipv4_black_list.txt")
      nft add element inet nftclash source_ipv4_list {$SOURCE_IPV4_BLACK_LIST}
    fi
    if [ -n "$(grep -v '^$' "$DIR/ruleset/source_ipv6_black_list.txt")" ]; then
      SOURCE_IPV6_BLACK_LIST=$(awk '{printf "%s, ",$1}' "$DIR/ruleset/source_ipv6_black_list.txt")
      nft add element inet nftclash source_ipv6_list {$SOURCE_IPV6_BLACK_LIST}
    fi
  }
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
  if [ "$PROXY_COMMON_PORT_MAC_LIST_ENABLED" = 1 ]; then
    [ ! -e "$DIR/ruleset/proxy_common_port_ether_list.txt" ] && touch "$DIR/ruleset/proxy_common_port_ether_list.txt"
    [ "$PROXY_COMMON_PORT_ENABLED" = 1 ] && init_proxy_common_port_mac_list
  fi
}

init_mac_white_list() {
  log_info "INIT MAC_WHITE_LIST"
  nft add set inet nftclash ether_list { type ether_addr\; } && \
  nft add rule inet nftclash prerouting ether saddr != @ether_list return && \
  nft add rule inet nftclash prerouting_nat ether saddr != @ether_list return
  if [ -n "$(grep -v '^$' "$DIR/ruleset/ether_white_list.txt")" ]; then
    MAC_WHITE_LIST=$(awk '{printf "%s, ",$1}' "$DIR/ruleset/ether_white_list.txt")
    nft add element inet nftclash ether_list {$MAC_WHITE_LIST}
  fi
}

init_mac_black_list() {
  log_info "INIT MAC_BLACK_LIST"
  nft add set inet nftclash ether_list { type ether_addr\; } && \
  nft add rule inet nftclash prerouting ether saddr @ether_list return && \
  nft add rule inet nftclash prerouting_nat ether saddr @ether_list return
  if [ -n "$(grep -v '^$' "$DIR/ruleset/ether_black_list.txt")" ]; then
    MAC_BLACK_LIST=$(awk '{printf "%s, ",$1}' "$DIR/ruleset/ether_black_list.txt")
    nft add element inet nftclash ether_list {$MAC_BLACK_LIST}
  fi
}

init_proxy_common_port_mac_list() {
  log_info "INIT PROXY_COMMON_PORT_MAC_LIST"
  COMMON_PORT_LIST=$(echo $PROXY_COMMON_PORT_LIST | sed 's/,/, /g')
  nft add set inet nftclash proxy_common_port_ether_list { type ether_addr\; } && \
  [ -n "$COMMON_PORT_LIST" ] && {
    nft add rule inet nftclash prerouting ether saddr @proxy_common_port_ether_list tcp dport != {$COMMON_PORT_LIST} return
    nft add rule inet nftclash prerouting ether saddr @proxy_common_port_ether_list udp dport != {$COMMON_PORT_LIST} return
  }
  if [ -n "$(grep -v '^$' "$DIR/ruleset/proxy_common_port_ether_list.txt")" ]; then
    PROXY_COMMON_PORT_MAC_LIST=$(awk '{printf "%s, ",$1}' "$DIR/ruleset/proxy_common_port_ether_list.txt")
    nft add element inet nftclash proxy_common_port_ether_list {$PROXY_COMMON_PORT_MAC_LIST}
  fi
}

init_force_proxy_ip() {
  log_info "INIT FORCE PROXY_IP"
  nft add set inet nftclash proxy_ip { type ipv4_addr\; flags interval\; } && \
  if [ -n "$(grep -v '^$' "$DIR/ipset/proxy_ip_list.txt")" ]; then
    PROXY_IP=$(awk '{printf "%s, ",$1}' "$DIR/ipset/proxy_ip_list.txt")
    nft add element inet nftclash proxy_ip {$PROXY_IP}
  fi
}

init_force_proxy_ipv6() {
  log_info "INIT FORCE PROXY_IP6"
  nft add set inet nftclash proxy_ip6 { type ipv6_addr\; flags interval\; } && \
  if [ -n "$(grep -v '^$' "$DIR/ipset/proxy_ipv6_list.txt")" ]; then
    PROXY_IP6=$(awk '{printf "%s, ",$1}' "$DIR/ipset/proxy_ipv6_list.txt")
    nft add element inet nftclash proxy_ip6 {$PROXY_IP6}
  fi
}

init_pass_ip_bypass() {
  log_info "INIT PASS_IP BYPASS"
  nft add set inet nftclash pass_ip { type ipv4_addr\; flags interval\; } && \
  nft add rule inet nftclash prerouting ip daddr @pass_ip return && \
  nft add rule inet nftclash prerouting_nat ip daddr @pass_ip return
  if [ -n "$(grep -v '^$' "$DIR/ipset/pass_ip_list.txt")" ]; then
    PASS_IP=$(awk '{printf "%s, ",$1}' "$DIR/ipset/pass_ip_list.txt")
    nft add element inet nftclash pass_ip {$PASS_IP}
  fi
}

init_pass_ipv6_bypass() {
  log_info "INIT PASS_IP6 BYPASS"
  nft add set inet nftclash pass_ip6 { type ipv6_addr\; flags interval\; } && \
  nft add rule inet nftclash prerouting ip6 daddr @pass_ip6 return && \
  nft add rule inet nftclash prerouting_nat ip6 daddr @pass_ip6 return
  if [ -n "$(grep -v '^$' "$DIR/ipset/pass_ipv6_list.txt")" ]; then
    PASS_IP6=$(awk '{printf "%s, ",$1}' "$DIR/ipset/pass_ipv6_list.txt")
    nft add element inet nftclash pass_ip6 {$PASS_IP6}
  fi
}

init_cn_ip_bypass() {
  if [ -e "$DIR/ipset/china_ip_list.txt" ]; then
    if [ -n "$(grep -v '^$' "$DIR/ipset/china_ip_list.txt")" ]; then
      log_info "INIT CN_IP BYPASS"
      CN_IP=$(awk '{printf "%s, ",$1}' "$DIR/ipset/china_ip_list.txt")
      nft add element inet nftclash cn_ip {$CN_IP}
    else
      log_warn "china_ip_list.txt is empty!!!"
      set_config VERSION_CHINA_IPLIST 0 "$VERSION_PATH"
      rm -f "$DIR/ipset/china_ip_list.txt"
    fi
  else
    log_warn "china_ip_list.txt is missing!!!"
    set_config VERSION_CHINA_IPLIST 0 "$VERSION_PATH"
  fi
}

init_cn_ipv6_bypass() {
  if [ -e "$DIR/ipset/china_ipv6_list.txt" ]; then
    if [ -n "$(grep -v '^$' "$DIR/ipset/china_ipv6_list.txt")" ]; then
      log_info "INIT CN_IP6 BYPASS"
      CN_IP6=$(awk '{printf "%s, ",$1}' "$DIR/ipset/china_ipv6_list.txt")
      nft add element inet nftclash cn_ip6 {$CN_IP6}
    else
      log_warn "china_ipv6_list.txt is empty!!!"
      set_config VERSION_CHINA_IPLIST 0 "$VERSION_PATH"
      rm -f "$DIR/ipset/china_ipv6_list.txt"
    fi
  else
    log_warn "china_ipv6_list.txt is missing!!!"
    set_config VERSION_CHINA_IPLIST 0 "$VERSION_PATH"
  fi
}

init_fw_bypass() {
  if [ "$FORCE_PROXY_IP_ENABLED" = 1 ]; then
    # IPv4 Rules
    if [ -e "$DIR/ipset/proxy_ip_list.txt" ]; then
      init_force_proxy_ip
    else
      log_warn "proxy_ip_list.txt does not exist!!!"
      echo "Creating proxy_ip_list.txt"
      touch "$DIR/ipset/proxy_ip_list.txt"
      init_force_proxy_ip
    fi
    # IPv6 Rules
    if [ -e "$DIR/ipset/proxy_ipv6_list.txt" ]; then
      init_force_proxy_ipv6
    else
      log_warn "proxy_ipv6_list.txt does not exist!!!"
      echo "Creating proxy_ipv6_list.txt"
      touch "$DIR/ipset/proxy_ipv6_list.txt"
      init_force_proxy_ipv6
    fi

    nft add rule inet nftclash prerouting ip daddr @proxy_ip jump transparent_proxy
    nft add rule inet nftclash prerouting ip6 daddr @proxy_ip6 jump transparent_proxy
  fi
  if [ "$BYPASS_PASS_IP_ENABLED" = 1 ]; then
    # IPv4 Rules
    if [ -e "$DIR/ipset/pass_ip_list.txt" ]; then
      init_pass_ip_bypass
    else
      log_warn "pass_ip_list.txt does not exist!!!"
      echo "Creating pass_ip_list.txt"
      touch "$DIR/ipset/pass_ip_list.txt"
      init_pass_ip_bypass
    fi
    # IPv6 Rules
    if [ -e "$DIR/ipset/pass_ipv6_list.txt" ]; then
      init_pass_ipv6_bypass
    else
      log_warn "pass_ipv6_list.txt does not exist!!!"
      echo "Creating pass_ipv6_list.txt"
      touch "$DIR/ipset/pass_ipv6_list.txt"
      init_pass_ipv6_bypass
    fi
  fi
  if [ "$BYPASS_CN_IP_ENABLED" = 1 ]; then
    if [ -e "$VERSION_PATH" ]; then
      source $VERSION_PATH
    else
      log_error "version file is missing!!!"
    fi
    # IPv4 Rules
    nft add set inet nftclash cn_ip { type ipv4_addr\; flags interval\; } && \
    nft add rule inet nftclash prerouting ip daddr @cn_ip return && \
    nft add rule inet nftclash prerouting_nat ip daddr @cn_ip return
    if [ "$VERSION_CHINA_IPLIST" = 0 ] || [ -z "$VERSION_CHINA_IPLIST" ]; then
      download_china_ip_list &
    else
      init_cn_ip_bypass
    fi
    # IPv6 Rules
    nft add set inet nftclash cn_ip6 { type ipv6_addr\; flags interval\; } && \
    nft add rule inet nftclash prerouting ip6 daddr @cn_ip6 return && \
    nft add rule inet nftclash prerouting_nat ip6 daddr @cn_ip6 return
    if [ "$VERSION_CHINA_IPLIST" = 0 ] || [ -z "$VERSION_CHINA_IPLIST" ]; then
      download_china_ipv6_list &
    else
      init_cn_ipv6_bypass
    fi
  fi
}

init_fw_dns() {
  dns_listen_ip=$(echo $clash_dns_listen | cut -d ":" -f 1)
  dns_listen_port=$(echo $clash_dns_listen | cut -d ":" -f 2)
  if [ "$clash_dns_enabled" = "true" ]; then
    if [ -z "$dns_listen_ip" ] || [ "$dns_listen_ip" == "0.0.0.0" ]; then
      log_info "INIT DNS_REDIRECT"
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
      log_error "You need to set the listening IP of clash dns to 0.0.0.0!!!"
    fi
  else
    log_error "Clash dns is not enabled!"
  fi
  
}

init_fw() {
  nft add table inet nftclash
  nft flush table inet nftclash
  nft add chain inet nftclash prerouting { type filter hook prerouting priority -100 \; }
  nft add chain inet nftclash prerouting_nat { type nat hook prerouting priority -110 \; }

  ip rule add fwmark $fwmark table 100 2> /dev/null
  ip route add local default dev lo table 100 2> /dev/null
  ip -6 rule add fwmark $fwmark table 101 2> /dev/null
  ip -6 route add local ::/0 dev lo table 101 2> /dev/null

  RESERVED_IP="$(echo $RESERVED_IPV4 | sed 's/ /, /g')"
  RESERVED_IP6="$(echo $RESERVED_IPV6 | sed 's/ /, /g')"
  nft add rule inet nftclash prerouting ip daddr {$RESERVED_IP} return
  nft add rule inet nftclash prerouting_nat ip daddr {$RESERVED_IP} return
  nft add rule inet nftclash prerouting ip6 daddr {$RESERVED_IP6} return
  nft add rule inet nftclash prerouting_nat ip6 daddr {$RESERVED_IP6} return

  nft add set inet nftclash loopback_ipv4_list { type ipv4_addr\; flags interval\; }
  nft add set inet nftclash loopback_ipv6_list { type ipv6_addr\; flags interval\; }
  nft add rule inet nftclash prerouting ip daddr @loopback_ipv4_list return
  nft add rule inet nftclash prerouting_nat ip daddr @loopback_ipv4_list return
  nft add rule inet nftclash prerouting ip6 daddr @loopback_ipv6_list return
  nft add rule inet nftclash prerouting_nat ip6 daddr @loopback_ipv6_list return

  loopback_check

  # Transparent proxy chain
  log_info "INIT TPROXY CHAIN"
  nft add chain inet nftclash transparent_proxy
  init_tproxy

  init_source_ip_list
  init_mac_list

  # Force proxy chain
  log_info "INIT FORCE PROXY CHAIN"
  nft add chain inet nftclash force_proxy
  nft add rule inet nftclash prerouting jump force_proxy
  nft add rule inet nftclash prerouting_nat jump force_proxy
  init_proxy_list

  # Bypass proxy chain
  log_info "INIT BYPASS PROXY CHAIN"
  nft add chain inet nftclash bypass_proxy
  nft add rule inet nftclash prerouting jump bypass_proxy
  nft add rule inet nftclash prerouting_nat jump bypass_proxy
  init_bypass_list

  [ "$BYPASS_SOURCE_PORT_ENABLED" = 1 ] && {
    SOURCE_PORT_LIST=$(echo $BYPASS_SOURCE_PORT_LIST | sed 's/,/, /g')
    [ -n "$SOURCE_PORT_LIST" ] && {
      nft add rule inet nftclash prerouting tcp sport {$SOURCE_PORT_LIST} return
      nft add rule inet nftclash prerouting udp sport {$SOURCE_PORT_LIST} return
    }
  }

  [ "$BYPASS_DEST_PORT_ENABLED" = 1 ] && {
    DEST_PORT_LIST=$(echo $BYPASS_DEST_PORT_LIST | sed 's/,/, /g')
    [ -n "$DEST_PORT_LIST" ] && {
      nft add rule inet nftclash prerouting tcp dport {$DEST_PORT_LIST} return
      nft add rule inet nftclash prerouting udp dport {$DEST_PORT_LIST} return
    }
  }

  [ "$PROXY_COMMON_PORT_MAC_LIST_ENABLED" = 0 ] && [ "$PROXY_COMMON_PORT_ENABLED" = 1 ] && {
    COMMON_PORT_LIST=$(echo $PROXY_COMMON_PORT_LIST | sed 's/,/, /g')
    [ -n "$COMMON_PORT_LIST" ] && {
      nft add rule inet nftclash prerouting tcp dport != {$COMMON_PORT_LIST} return
      nft add rule inet nftclash prerouting udp dport != {$COMMON_PORT_LIST} return
    }
  }

  [ "$BYPASS_53_TCP" = 1 ] && nft add rule inet nftclash prerouting tcp dport 53 return
  [ "$BYPASS_53_UDP" = 1 ] && nft add rule inet nftclash prerouting udp dport 53 return

  init_fw_bypass

  nft add rule inet nftclash prerouting jump transparent_proxy

  [ "$ICMP_REDIRECT" = 1 ] && {
    nft add rule inet nftclash prerouting_nat meta l4proto icmp redirect
    nft add rule inet nftclash prerouting_nat meta l4proto ipv6-icmp redirect
  }

  [ "$DNS_REDIRECT" = 1 ] && init_fw_dns

  log_info "INIT LOCAL_PROXY"

  # Local Proxy
  nft add chain inet nftclash output { type nat hook output priority -100 \; }
  nft add rule inet nftclash output meta skgid 7890 return
  nft add rule inet nftclash output ip daddr {$RESERVED_IP} return
  nft add rule inet nftclash output ip6 daddr {$RESERVED_IP6} return

  nft add rule inet nftclash output ip daddr @loopback_ipv4_list return
  nft add rule inet nftclash output ip6 daddr @loopback_ipv6_list return

  nft add rule inet nftclash output jump bypass_proxy

  [ "$BYPASS_SOURCE_PORT_ENABLED" = 1 ] && {
    SOURCE_PORT_LIST=$(echo $BYPASS_SOURCE_PORT_LIST | sed 's/,/, /g')
    [ -n "$SOURCE_PORT_LIST" ] && {
      nft add rule inet nftclash output tcp sport {$SOURCE_PORT_LIST} return
    }
  }

  [ "$BYPASS_DEST_PORT_ENABLED" = 1 ] && {
    DEST_PORT_LIST=$(echo $BYPASS_DEST_PORT_LIST | sed 's/,/, /g')
    [ -n "$DEST_PORT_LIST" ] && {
      nft add rule inet nftclash output tcp dport {$DEST_PORT_LIST} return
    }
  }

  [ "$PROXY_COMMON_PORT_ENABLED" = 1 ] && [ "$PROXY_COMMON_PORT_LOCAL_ENABLED" = 1 ] && {
    COMMON_PORT_LIST=$(echo $PROXY_COMMON_PORT_LIST | sed 's/,/, /g')
    [ -n "$COMMON_PORT_LIST" ] && {
      nft add rule inet nftclash output tcp dport != {$COMMON_PORT_LIST} return
    }
  }

  [ "$LOCAL_PROXY_BYPASS_53" = 1 ] && nft add rule inet nftclash output tcp dport 53 return

  [ "$BYPASS_PASS_IP_ENABLED" = 1 ] && nft add rule inet nftclash output ip daddr @pass_ip return
  [ "$BYPASS_PASS_IP_ENABLED" = 1 ] && nft add rule inet nftclash output ip6 daddr @pass_ip6 return
  [ "$BYPASS_CN_IP_ENABLED" = 1 ] && nft add rule inet nftclash output ip daddr @cn_ip return
  [ "$BYPASS_CN_IP_ENABLED" = 1 ] && nft add rule inet nftclash output ip6 daddr @cn_ip6 return

  [ "$LOCAL_PROXY_IPV6" = 0 ] && nft add rule inet nftclash output meta nfproto ipv6 return

  [ "$REJECT_QUIC" = 1 ] && nft add rule inet nftclash output udp dport { 443, 8443 } reject
  nft add rule inet nftclash output meta l4proto tcp mark set $fwmark redirect to $redir_port
  log_info "INIT FIREWALL_RULES DONE!"
}

init_tproxy() {
  if nft -j list chain inet nftclash transparent_proxy 2> /dev/null | \
     jq -e '.nftables | map(select(.rule)) | length == 0' >/dev/null;
  then
    [ "$REJECT_QUIC" = 1 ] && nft add rule inet nftclash transparent_proxy udp dport { 443, 8443 } reject
    nft add rule inet nftclash transparent_proxy meta l4proto { tcp, udp } mark set $fwmark tproxy to :$tproxy_port
  fi
}

init_startup() {
  ! modprobe nft_tproxy && {
    log_error "missing nft_tproxy!!!"
    return 1
  }
  if ! command -v yq >/dev/null 2>&1; then
    log_error "You need to install yq!!!"
    return 1
  fi
  if ! command -v jq >/dev/null 2>&1; then
    log_error "You need to install jq!!!"
    return 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    log_error "You need to install curl!!!"
    return 1
  fi
  if [ -e "$CLASH_HOME_DIR/clash" ]; then
    if [ -e "$CLASH_HOME_DIR/config.yaml" ]; then
      chmod 777 -R "$DIR"
      log_info "INIT STARTUP DONE!"
    else
      log_warn "Please manually move the clash config file to $CLASH_HOME_DIR/config.yaml"
      return 1
    fi
  else
    echo "clash file does not exist!!!"
    if [ ! -d "$CLASH_HOME_DIR" ]; then
      echo "Creating directory"
      mkdir -p "$CLASH_HOME_DIR"
      log_warn "Please manually restart service!"
      return 1
    fi
    log_warn "Please manually move the clash executable file to $CLASH_HOME_DIR/clash"
    return 1
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
  # env
  [ ! -d "$DIR/env" ] && mkdir -p "$DIR/env"
  [ ! -e "$DIR/env/DISABLE_EMBED_CA" ] && touch "$DIR/env/DISABLE_EMBED_CA"
  [ ! -e "$DIR/env/DISABLE_SYSTEM_CA" ] && touch "$DIR/env/DISABLE_SYSTEM_CA"
  [ ! -e "$DIR/env/DISABLE_LOOPBACK_DETECTOR" ] && touch "$DIR/env/DISABLE_LOOPBACK_DETECTOR"
  [ ! -e "$DIR/env/SKIP_SYSTEM_IPV6_CHECK" ] && touch "$DIR/env/SKIP_SYSTEM_IPV6_CHECK"
  [ ! -e "$DIR/env/SKIP_SAFE_PATH_CHECK" ] && touch "$DIR/env/SKIP_SAFE_PATH_CHECK"
  [ ! -e "$DIR/env/SAFE_PATHS" ] && touch "$DIR/env/SAFE_PATHS"
  return 0
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
  log_info "${GREEN}API_URL: ${NOCOLOR}http://${HOST_IPV4}:${CLASH_API_PORT}"
  log_info "${GREEN}API_URL: ${NOCOLOR}http://[${HOST_IPV6}]:${CLASH_API_PORT}"
  [ "$INIT_CHECKS_ENABLED" = 0 ] && {
    init_fw
    log_info "CLASH SERVICE STARTED"
    CLASH_API_READY=1
  }
  return 0
}

init_check() {
  [ "$INIT_CHECKS_ENABLED" = 1 ] && {
    CHECK_FAILURE=0
    CHECK_FAILURE_COUNT=0
    while [ "$CHECK_FAILURE_COUNT" -le 30 ]; do
        clash_api_fetch &> /dev/null
        if [ $? -eq 0 ]; then
          CHECK_FAILURE=0
          init_fw
          log_info "CLASH SERVICE STARTED"
          CLASH_API_READY=1
          break
        fi
        CHECK_FAILURE_COUNT=$(( CHECK_FAILURE_COUNT + 1 ))
        CHECK_FAILURE=1
        sleep 1
    done
    if [ "$CHECK_FAILURE" = 1 ];then
      log_error "CLASH TIMEDOUT!!!"
      return 1
    fi
  }
}

flush_tproxy() {
  if nft -j list chain inet nftclash transparent_proxy 2> /dev/null | \
     jq -e '.nftables | map(select(.rule)) | length != 0' >/dev/null;
  then
    nft flush chain inet nftclash transparent_proxy
  fi
}

flush_fw() {
  nft list table inet nftclash&> /dev/null && {
    nft flush table inet nftclash
    nft delete table inet nftclash
  }
}

log info "$0 $*"
init_config
init_clash_api
case "$1" in
  init_startup)
    init_startup
    ;;
  init_started)
    init_started
    ;;
  init_fw)
    init_fw
    ;;
  reinit_fw)
    flush_fw
    init_fw
    ;;
  flush_fw)
    flush_fw
    ;;
  init_tproxy)
    init_tproxy
    ;;
  flush_tproxy)
    flush_tproxy
    [ "$2" = "force" ] && clash_api_fetch DELETE connections
    ;;
  check_update)
    check_update $2
    ;;
  reload_clash_config)
    reload_clash_config $2
    ;;
  update_clash_config)
    update_clash_config
    ;;
  silent_update_china_iplist)
    silent_update_china_iplist
    ;;
  silent_update_clash_config)
    silent_update_clash_config
    ;;
  silent_update)
    silent_update_china_iplist
    silent_update_clash_config
    ;;
  get_conf)
    get_conf $2
    ;;
  set_conf)
    set_conf $2 $3 $4
    ;;
  update_config)
    init_config update
    ;;
  hotplug)
    log_info "hotplug: $2 ($3)"
    loopback_check
    ;;
  conn_check)
    CLASH_API_READY=1
    connection_check
    ;;
  init_check)
    init_check
    ;;
  init_conn_check)
    init_check
    connection_check
    ;;
  clash_api_fetch)
    clash_api_fetch $2 $3 $4
    ;;
  test_log_print)
    log_info "log_info"
    log_warn "log_warn"
    log_error "log_error"
    ;;
  *)
    return 1
    ;;
esac

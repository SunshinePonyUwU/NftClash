<h1 align="center">
  <img src="logo.png?raw=true" alt="Clash" width="200">
  <br>Nft Clash<br>
</h1>
使用nftables实现的clash透明代理客户端

功能介绍:
--
更简洁的透明代理  
中国大陆IP绕过内核  
指定IP绕过内核

系统支持：
--
使用nftables的OpenWrt系统（23版本以上）

所需软件包：
--
- kmod-nft-tproxy
- yq
- jq
- curl

如何安装：
--
1.下载源码ZIP  
2.解压 install_files 内的文件到 /etc/nftclash/install 文件夹内  
3.设置 /etc/nftclash 文件夹权限为 777  
```shell
chmod +x -R /etc/nftclash
```
4.执行以下脚本安装服务  
```shell
/etc/nftclash/install/install.sh
```
5.手动下载Clash内核可执行文件  
- 前往[Mihomo发布页](https://wiki.metacubex.one/startup/#__tabbed_2_2)找到你路由器的系统架构
- 下载文件名格式为 <u>mihomo-linux-xxxx-compatible-xxxx.gz</u> 二进制压缩包
- 解压后将二进制文件移动到 /etc/nftclash/clash/clash

6.手动放置Clash配置文件  
_(不建议直接使用机场提供的配置文件)_  
7.执行以下命令启动服务  
```shell
service nftclash start
```

检查脚本或CNIP更新
--
_CHINA IP LIST 更新后会立即生效，无需重启clash服务_
```shell
/etc/nftclash/service.sh check_update
```
更新clash配置文件  
_(需设置CLASH_CONFIG_UPDATE)_  
```shell
/etc/nftclash/service.sh update_clash_config
```
计划任务示例:  
每天早上八點執行  
```shell
0 8 * * * pgrep clash && /etc/nftclash/service.sh silent_update
```
静默更新CHINA IP LIST和clash配置文件
```shell
/etc/nftclash/service.sh silent_update
```
静默更新CHINA IP LIST
```shell
/etc/nftclash/service.sh silent_update_china_iplist
```
静默更新clash配置文件
```shell
/etc/nftclash/service.sh silent_update_clash_config
```


nftclash服务配置：
--
| 配置选项 | 默认值 | 可接受的值 | 配置描述 |
| :- | :- | :- | :- |
| BYPASS_SOURCE_PORT_ENABLED | 0 | 0,1 | 绕过指定的源端口 |
| BYPASS_SOURCE_PORT_LIST | "0-1023,8000-8880" | "PORT,PORT,PORT,..." | 源端口列表 |
| BYPASS_DEST_PORT_ENABLED | 0 | 0,1 | 绕过指定的目标端口 |
| BYPASS_DEST_PORT_LIST | "123,3478-3479" | "PORT,PORT,PORT,..." | 目标端口列表 |
| PROXY_COMMON_PORT_ENABLED | 0 | 0,1 | 仅代理常用端口 |
| PROXY_COMMON_PORT_LIST | "22,53,80,..." | "PORT,PORT,PORT,..." | 常用端口列表 |
| PROXY_COMMON_PORT_LOCAL_ENABLED | 0 | 0,1 | 本机代理仅代理常用端口 |
| PROXY_COMMON_PORT_MAC_LIST_ENABLED | 0 | 0,1 | 常用端口代理仅对MAC列表生效 |
| BYPASS_CN_IP_ENABLED | 1 | 0,1 | 启用绕过中国大陆IP |
| BYPASS_PASS_IP_ENABLED | 1 | 0,1 | 启用绕过指定IP |
| FORCE_PROXY_IP_ENABLED | 1 | 0,1 | 启用代理指定IP |
| SOURCE_IP_LIST_MODE | 0 | 0,1,2 | 0:禁用,1:源IP白名单,2:源IP黑名单 |
| MAC_LIST_MODE | 0 | 0,1,2 | 0:禁用,1:MAC白名单,2:MAC黑名单 |
| LOCAL_PROXY_IPV6 | 0 | 0,1 | 本机代理代理IPv6 |
| LOCAL_PROXY_BYPASS_53 | 0 | 0,1 | 本机代理绕过TCP53端口 |
| BYPASS_53_TCP | 0 | 0,1 | 不代理TCP DNS |
| BYPASS_53_UDP | 0 | 0,1 | 不代理UDP DNS |
| REJECT_QUIC | 0 | 0,1 | 丢弃QUIC数据包 |
| ICMP_REDIRECT | 0 | 0,1 | 重定向ICMP (PING) |
| LOOPBACK_CHECKS_ENABLED | 1 | 0,1 | 启用环回检查 |
| INIT_CHECKS_ENABLED | 1 | 0,1 | 初始化检查，可以避免clash未启动完成时短暂断网 |
| CONN_CHECKS_ENABLED | 1 | 0,1 | 连接检查，服务启动后连接测试失败就清除透明代理规则 |
| CONN_CHECKS_FORCE | 0 | 0,1 | 连接检查清除规则时同时关闭已有连接 |
| CONN_CHECKS_INTERVAL | 300 | int | 连接检查间隔 |
| CONN_CHECKS_RETRY_INTERVAL | 8 | int | 连接检查重试间隔 |
| CONN_CHECKS_MAX_FAILURES | 5 | int | 连接检查允许的最大失败次数 |
| CONN_CHECKS_MIN_SUCCESSES | 5 | int | 连接检查允许的最下成功次数 |
| CONN_CHECKS_URL | http://cp.cloudflare.com/ | (URL) | 连接检查的URL |
| CLASH_CONFIG_UPDATE_ENABLED | 0 | 0,1 | 启用clash配置文件更新 |
| CLASH_CONFIG_UPDATE_URL | "" | (URL) | clash配置文件下载连接 |
| CLASH_CONFIG_UPDATE_UA | "" | (UA) | 更新clash配置文件的User-Agent |
| CLASH_LOG_STDOUT | 0 | 0,1 | 是否把clash输出打印到系统日志 |
修改配置后使用以下命令更新防火墙规则
```shell
service nftclash reload_fw
```

不建议使用Clash的DNS作为路由器代理的DNS服务器  
我们更建议单独配置mosdns作为DNS  

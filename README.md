<h1 align="center">
  <img src="https://github.com/SunshinePonyUwU/NftClash/blob/main/logo.png?raw=true" alt="Clash" width="200">
  <br>Nft Clash<br>
</h1>
使用NFT實現透明代理的Clash客戶端

功能介紹：
--
簡潔的透明代理  
支持繞過中國大陸IP  
支持繞過指定IP  
支持在指定IP匹配以上兩個規則時仍然代理

系統支持：
--
使用nftables的OpenWrt系統（23版本以上）

安裝方式：
--
1.下載源代碼
2.解壓 install_files 文件夾的内容到 /etc/nftclash/install 文件夾下  
3.設置 /etc/nftclash 文件夾權限為 777  
4.執行 /etc/nftclash/install/install.sh  
5.執行 service nftclash start 啓動clash服務  

功能配置：
--
| 選項 | 默認值 | 可接受的值 | 描述 |
| :- | :- | :- | :- |
| DNS_REDIRECT | 0 | 0,1 | 啓用DNS重定向 |
| PROXY_COMMON_PORT_ENABLED | 0 | 0,1 | 僅代理常用端口 |
| PROXY_COMMON_PORT_LIST | "22,53,80,..." | "PORT,PORT,PORT,..." | 常用端口列表 |
| BYPASS_CN_IP_ENABLED | 1 | 0,1 | 啓用繞過中國大陸IP |
| BYPASS_PASS_IP_ENABLED | 1 | 0,1 | 啓用繞過指定IP |
| FORCE_PROXY_IP_ENABLED | 1 | 0,1 | 啓用代理指定IP |
| MAC_LIST_MODE | 0 | 0,1,2 | 0:禁用功能,1:MAC白名單模式,2:MAC黑名單模式 |

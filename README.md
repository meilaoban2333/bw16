# BW16 WiFi 工具箱（Deauth 攻击 + WPA 握手抓包 二合一）

把 [RTL8720dn-Deauther](https://github.com/tesa-klebeband/RTL8720dn-Deauther) 与
[RTL8720dn-Handshake-Capture](https://github.com/Cancro29/RTL8720dn-Handshake-Capture)
两个项目合并为一个固件，运行在 BW16（RTL8720dn）开发板上，提供**全中文网页**操作界面。

## ⚠ 免责声明与使用范围

本工具是一个**无线安全研究 / 教学用途**的固件，仅可用于以下场景：

- 在**你本人拥有或完全控制**的网络与设备上做测试；
- 在取得**书面授权**的渗透测试、安全课程或 CTF 等环境中使用。

Deauth（断网）属于对无线网络的拒绝服务攻击，握手抓包用于离线还原 WPA/WPA2 口令。
**在未经授权的网络上使用上述功能，在中国大陆及绝大多数国家/地区均属违法行为。**
使用本工具即表示你已理解并同意：一切使用行为及其后果由使用者本人承担全部法律责任，
作者与整合者不对任何滥用或由此造成的损失负责。请在使用前确认你的测试对象已获得明确授权。

## 功能

- **扫描**：列出周边 2.4GHz / 5GHz 的 WiFi，显示信道、BSSID、信号强度。
- **断网攻击（Deauth）**：勾选一个或多个网络，持续发送 deauth 帧，踢掉其已连接的客户端；可调整每次发送帧数与发送间隔。
- **在线客户端检测**：对选定目标纯监听约 4 秒，列出当前与该 AP 通信的客户端 MAC（作为「标识码」），据此判断是否适合抓包——有客户端在线时 deauth 才能逼其重连、抓到握手。
- **握手抓包（Handshake Capture）**：选定单个目标，自动「deauth + 混杂模式嗅探」，抓到 WPA/WPA2 四次握手后生成 `handshake.pcap` 供下载，可用 Wireshark / hashcat / aircrack 做后续分析。
- **RGB 状态指示**：板载 RGB 灯反映运行状态——待机时绿灯常亮，抓包 / 在线客户端探测 / 攻击期间紫灯（红+蓝）常亮，便于在无串口时判断设备状态。

攻击与抓包为两套独立模式：攻击可多选目标，抓包针对单一目标；开始抓包时会自动停止正在进行的攻击。

### 关于 PCAP 格式与「可用握手」

- PCAP 使用 **DLT_IEEE802_11 (link type 105)**，即裸 802.11 帧、无 radiotap，并剥去帧尾 4 字节 FCS——这是 hashcat / aircrack / Wireless Password Recovery 等工具兼容性最好的格式。
  （早期版本用 DLT 127 + 伪造 radiotap 头，会导致 EAPOL 长度错位、破解工具「检测不到握手」。）
- 固件会解析 EAPOL-Key 的 Key Information 字段，识别四次握手的 **M1/M2/M3/M4**。只要抓到 **M1+M2** 或 **M2+M3**（含 ANonce / SNonce / MIC）即视为「可用于破解」的握手，网页会逐步显示各 message 的捕获状态，不再死等 4 帧。

## 文件结构

源码均位于 `wifi/` 目录下：

| 文件 | 说明 |
| --- | --- |
| `wifi/wifi.ino` | 主程序：SoftAP、Web 服务器、扫描、deauth 攻击循环、路由分发 |
| `wifi/handshake.h` | 握手抓取逻辑、PCAP 生成与下载 |
| `wifi/webpage.h` | 全中文网页界面（深色主题） |
| `wifi/wifi_cust_tx.h` / `wifi/wifi_cust_tx.cpp` | 802.11 原始帧发送（来自 tesa-klebeband 的 packet-injection，自包含，不依赖子模块） |

## 编译与烧录

1. 用 Arduino IDE，在开发板管理器中添加 Realtek Ameba 的板子索引并安装：
   `https://raw.githubusercontent.com/Ameba-AIoT/ameba-arduino-d/master/Arduino_package/package_realtek_amebad_index.json`
   （握手抓取部分在 **AmebaD SDK 3.1.7** 上验证可用。）
2. 用 Arduino IDE 打开 `wifi` 文件夹（会一并加载同目录下的 `.h` / `.cpp`）。
3. 选择你的 BW16 开发板，连接后点击上传。
4. 多数 BW16 开发板上传时需短接 **LOG_UART_TX↔LP_UART_TX**、**LOG_UART_RX↔LP_UART_RX**。

## 使用

1. 烧录后设备会建立热点：
   - 名称（SSID）：`BW16-WiFi-Tool`
   - 密码：`0123456789`
   - 可在 `wifi.ino` 顶部的 `ap_ssid` / `ap_pass` / `ap_channel` 修改。
2. 手机或电脑连接该热点，浏览器访问 **192.168.1.1**。
3. 网页操作：
   - 点「重新扫描」刷新网络列表。
   - 勾选若干网络 → 点「对勾选网络发动断网攻击」；点「停止断网攻击」结束。
   - 在某网络行点「选为目标」→ 点「开始抓取握手包」，等约 10 秒自动返回首页；
     若抓到完整握手，会出现「下载 PCAP」按钮。
   - 可在「攻击参数设置」里调整每次发送帧数与发送间隔。

## 致谢

- 发包与 Deauther：[tesa-klebeband](https://github.com/tesa-klebeband/)
- 嗅探代码：[Nickguitar](https://github.com/Nickguitar/)
- 握手抓取整合：[Cancro29](https://github.com/Cancro29/)

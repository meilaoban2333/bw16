/*
 * webpage.h —— 全中文网页界面
 *
 * 样式沿用 RTL8720dn-Deauther 的深色主题(基于 Spacehuhn 的 CSS)。
 * 页面包含：网络列表(可多选 deauth / 单选抓包)、攻击控制、握手抓取、参数设置。
 *
 * 需在 wifi.ino 中各状态变量定义之后 #include。
 */
#ifndef WEBPAGE_H
#define WEBPAGE_H

// 这些函数/变量定义在 wifi.ino 或 handshake.h 中，此处前向声明以供本文件使用
String makeResponse(int code, String content_type);
String makeRedirect(String url);

// 握手抓取进度等待页：12 秒后自动跳回首页
String makeCaptureWaitPage() {
  String response = makeResponse(200, "text/html");
  response += R"(
  <!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=0.9">
  <title>正在抓取握手包</title>
  <style>
    body{background:#36393e;color:#bfbfbf;font-family:sans-serif;text-align:center;padding-top:50px;}
    h1{color:#43B581;font-weight:100;}
    .tip{margin-top:16px;color:#888;}
    .warn{margin-top:16px;color:#FAA61A;font-weight:bold;}
  </style>
  </head><body>
    <h1>正在后台持续抓取握手包…</h1>
    <p class="warn">⚠ 抓包期间本热点会断开，这是单天线设备的正常现象，不是故障。</p>
    <p class="tip">设备会<b>持续</b>在目标信道 deauth 并嗅探，抓到完整握手(M1+M2)后<b>自动停止</b>并回到热点。</p>
    <p class="tip">进度可在串口(115200)每 5 秒查看一次。若长时间抓不到，可<b>手动重启设备</b>重来。</p>
    <p class="tip">当热点 BW16-WiFi-Tool 重新出现后，连接并打开 192.168.1.1 查看结果、下载 PCAP。</p>
  </body></html>
  )";
  return response;
}

// 在线客户端检测等待页：6 秒后自动跳回首页
String makeClientScanWaitPage() {
  String response = makeResponse(200, "text/html");
  response += R"(
  <!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=0.9">
  <title>正在检测在线客户端</title>
  <style>
    body{background:#36393e;color:#bfbfbf;font-family:sans-serif;text-align:center;padding-top:60px;}
    h1{color:#43B581;font-weight:100;}
    .tip{margin-top:20px;color:#888;}
  </style>
  <script>setTimeout(function(){window.location.href='http://192.168.1.1/';},9000);</script>
  </head><body>
    <h1>正在检测目标在线客户端，请稍候…</h1>
    <p class="tip">设备正在监听目标 WiFi 的通信，约需 4 秒，期间热点可能短暂断开。</p>
    <p class="tip">页面将在约 9 秒后自动返回；若未跳转，请重连热点后打开 192.168.1.1。</p>
  </body></html>
  )";
  return response;
}

// 生成一个网络列表表格行(供 2.4G / 5G 两张表复用)
// idx：在 scan_results 中的下标
static String makeNetworkRow(uint32_t idx) {
  String color = "";
  int width = scan_results[idx].rssi + 120;      // 信号条宽度
  int colorWidth = scan_results[idx].rssi + 130; // 用于决定颜色档位
  if (colorWidth < 50) color = "meter_red";
  else if (colorWidth < 70) color = "meter_orange";
  else color = "meter_green";

  String row = "<tr>";
  row += "<td>" + String((scan_results[idx].ssid.length() > 0) ? scan_results[idx].ssid : "**隐藏网络**") + "</td>";
  row += "<td class='tdFixed'>" + String(scan_results[idx].channel) + "</td>";
  row += "<td>" + scan_results[idx].bssid_str + "</td>";
  row += "<td class='tdMeter'><div class='meter_background'><div class='meter_forground " + color +
         "' style='width: " + String(width) + "%'><div class='meter_value'>" + String(scan_results[idx].rssi) + "</div></div></div></td>";
  // deauth 多选框
  row += "<td><label class='checkBoxContainer'><input type='checkbox' name='network' value='" + String(idx) +
         "'><span class='checkmark'></span></label></td>";
  // 抓包目标单选按钮(标记当前选中项)
  bool selected = hasTarget &&
                  (memcmp(scan_results[idx].bssid, hs_target_bssid, 6) == 0);
  row += "<td><form method='post' action='/select' style='margin:0'>"
         "<input type='hidden' name='target' value='" + String(idx) + "'>";
  if (selected) row += "<input type='submit' value='已选' style='background:#0e62c2'>";
  else row += "<input type='submit' value='选为目标'>";
  row += "</form></td>";
  row += "</tr>";
  return row;
}

// 首页
void handleRoot(WiFiClient &client) {
  String response = makeResponse(200, "text/html") + R"(
  <!DOCTYPE html>
  <html lang="zh-CN">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=0.8, minimal-ui">
    <meta name="theme-color" content="#36393E">
    <title>BW16 WiFi 工具箱</title>
    <style>
    /* 样式基于 Spacehuhn 的 CSS，版权 (c) 2020 Spacehuhn Technologies */
      body { background:#36393e; color:#bfbfbf; font-family:sans-serif; }
      h1 { font-size:1.7rem; margin-top:1rem; background:#2f3136; color:#bfbfbb;
           padding:.2em 1em; border-radius:3px; border-left:solid #20c20e 5px;
           border-right:solid #20c20e 5px; font-weight:100; text-align:center; }
      h2 { font-size:1.1rem; margin-top:1rem; background:#2f3136; color:#bfbfbb;
           padding:.4em 1em; border-radius:3px; border-left:solid #20c20e 5px; font-weight:100; }
      h3 { background:#2f3136; color:#bfbfbb; padding:.2em 1em; border-radius:3px;
           font-weight:100; text-align:center; width:50%; }
      .centered { display:flex; justify-content:center; }
      table { border-collapse:collapse; width:100%; min-width:auto; margin-bottom:2em; }
      td { word-break:keep-all; text-align:left; border-bottom:1px solid #5d5d5d; }
      .tdMeter { word-break:break-all; padding-right:10px; text-align:left; border-bottom:1px solid #5d5d5d; }
      .tdFixed { word-break:keep-all; padding:10px 6px; text-align:center; border-bottom:1px solid #5d5d5d; }
      th { word-break:break-word; text-align:left; border-bottom:1px solid #5d5d5d; }
      p { margin:.5em 0; }
      .bold { font-weight:bold; }
      .right { display:flex; flex-direction:row-reverse; }
      .container { display:flex; flex-direction:column; width:100%; }
      .notice { background:#2f3136; border-left:solid #FAA61A 5px; padding:.6em 1em;
                border-radius:3px; font-size:.85rem; color:#d8a657; }
      .checkBoxContainer { display:block; position:relative; padding-left:25px; margin-bottom:12px;
                           cursor:pointer; font-size:22px; user-select:none; height:32px; }
      .checkBoxContainer input { position:absolute; opacity:0; cursor:pointer; }
      .checkmark { position:absolute; top:8px; left:0; height:28px; width:28px;
                   background-color:#2F3136; border-radius:4px; }
      .checkmark:after { content:""; position:absolute; display:none; }
      .checkBoxContainer input:checked ~ .checkmark:after { display:block; }
      .checkBoxContainer .checkmark:after { left:10px; top:7px; width:4px; height:10px;
                   border:solid white; border-width:0 3px 3px 0; transform:rotate(45deg); }
      .meter_background { background:#42464D; word-break:normal; }
      .meter_forground { color:#fff; padding:4px 0; }
      .meter_green { background:#43B581; }
      .meter_orange { background:#FAA61A; }
      .meter_red { background:#F04747; }
      .meter_value { padding-left:8px; }
      hr { background:#3e4146; }
      .button-container { display:flex; justify-content:start; align-items:center;
                          align-content:center; column-gap:15px; }
      .button-double { display:flex; flex-direction:column; justify-content:start;
                       align-items:center; align-content:center; row-gap:15px; }
      .button, button, input[type=submit], input[type=reset], input[type=button] {
        display:inline-block; height:38px; color:#fff; text-align:center; font-size:11px;
        font-weight:600; line-height:38px; letter-spacing:.1rem; text-decoration:none;
        white-space:nowrap; background:#2f3136; border-radius:4px; border:0; cursor:pointer;
        box-sizing:border-box; padding:0 12px; }
      button:hover, input[type=submit]:hover { background:#42444a; }
      button:active, input[type=submit]:active { transform:scale(.93); }
      input[type=text], input[type=number], select {
        text-align:center; height:38px; padding:0 5px; }
      .longInput { width:138px; }
      .green { border-bottom:solid #43B581 3px; }
      .red { border-bottom:solid #F04747 3px; }
    </style>
  </head>
  <body>
  <div class="container">
    <h1 class="bold">BW16 WiFi 工具箱</h1>
    <p class="notice">⚠ 本工具仅用于学习与授权测试。请勿在未授权的网络上使用，否则后果自负。</p>

    <div class="right">
      <div class="button-container">
        <form method="post" action="/rescan"><input type="submit" value="重新扫描"></form>
        <form method="post" action="/refresh"><input type="submit" value="刷新页面"></form>
      </div>
    </div>

    <form method="post" action="/deauth">
    <h2>扫描到的网络数量：)" + String(scan_results.size()) + R"(</h2>
    <p style="font-size:.85rem;color:#888;">说明：勾选左侧复选框可对一个或多个网络发动 <b>断网攻击(Deauth)</b>；点击右侧「选为目标」则把该网络设为 <b>握手抓包</b> 的单一目标。</p>

    <div class="centered"><h3 class="bold">5 GHz 网络</h3></div>
    <table>
      <tr><th>名称(SSID)</th><th class='tdFixed'>信道</th><th>BSSID</th><th>信号</th>
          <th class='tdFixed'>攻击</th><th>抓包目标</th></tr>
  )";

  // 5GHz 网络(信道 >= 36)
  for (uint32_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].channel >= 36) response += makeNetworkRow(i);
  }

  response += R"(
    </table>
    <div class="centered"><h3 class="bold">2.4 GHz 网络</h3></div>
    <table>
      <tr><th>名称(SSID)</th><th class='tdFixed'>信道</th><th>BSSID</th><th>信号</th>
          <th class='tdFixed'>攻击</th><th>抓包目标</th></tr>
  )";

  // 2.4GHz 网络(信道 <= 14)
  for (uint32_t i = 0; i < scan_results.size(); i++) {
    if (scan_results[i].channel <= 14) response += makeNetworkRow(i);
  }

  response += R"(
    </table>
    <div class="right"><div class="button-container">
      <input type="submit" value="对勾选网络发动断网攻击">
    </div></div>
    </form>

    <div class="right"><form method="post" action="/stop"><div class="button-container">
      <input class="red" type="submit" value="停止断网攻击">
    </div></form></div>

    <h2>握手包抓取(WPA / WPA2)</h2>
  )";

  // 握手抓取区域：根据当前状态显示不同内容
  response += "<table>";
  if (hasTarget) {
    response += "<tr><td>当前抓包目标</td><td>" +
                String(hs_target_ssid.length() > 0 ? hs_target_ssid : "**隐藏网络**") +
                "（信道 " + String(hs_target_channel) + "）</td></tr>";
  } else {
    response += "<tr><td>当前抓包目标</td><td>未选择（请在上方网络列表点击「选为目标」）</td></tr>";
  }
  // 在线客户端检测结果
  if (hasTarget) {
    if (!clientScanDone) {
      response += "<tr><td>在线客户端</td><td>尚未检测（点击下方「检测在线客户端」）</td></tr>";
    } else if (onlineClients.empty()) {
      response += "<tr><td>在线客户端</td><td>⚠ 未检测到在线客户端，此时抓包通常会失败，建议等有人上线再抓</td></tr>";
    } else {
      // 列出每个客户端 MAC 作为标识码
      String list = "共 " + String(onlineClients.size()) + " 个，可以抓包：<br>";
      for (auto &c : onlineClients) list += "• " + c.mac_str + "<br>";
      response += "<tr><td>在线客户端</td><td>" + list + "</td></tr>";
    }
  }
  response += "<tr><td>已集齐的握手步数</td><td>" + String(capturedHandshake.frameCount) +
              " / 4</td></tr>";
  // 逐个显示 M1~M4 是否抓到，帮助判断握手是否可用于破解
  String msgs = "";
  for (int m = 1; m <= 4; m++) msgs += "M" + String(m) + (gotMessage[m] ? "✅ " : "❌ ");
  response += "<tr><td>四次握手各步</td><td>" + msgs + "</td></tr>";
  bool best = gotMessage[1] && gotMessage[2];
  bool fallback = gotMessage[2] && gotMessage[3];
  String verdict;
  if (best) verdict = "✅ 最佳（M1+M2，含 ANonce/SNonce/MIC），破解工具普遍可用，可下载 PCAP";
  else if (fallback) verdict = "⚠ 次优（仅 M2+M3，缺 M1），部分工具可能不认，建议重抓获取 M1+M2";
  else verdict = "否（需要 M1+M2）";
  response += "<tr><td>是否可用于破解</td><td>" + verdict + "</td></tr>";
  response += "</table>";

  response += R"(
    <div class="right"><div class="button-container">
  )";
  // 有目标才显示“检测在线客户端”和“开始抓取”按钮
  if (hasTarget) {
    response += R"(<form method="post" action="/scanclients"><input type="submit" value="检测在线客户端"></form>)";
    response += R"(<form method="post" action="/capture"><input class="green" type="submit" value="开始抓取握手包"></form>)";
  }
  // 抓到了才显示“下载 PCAP / 清空”按钮
  if (isHandshakeCaptured) {
    response += R"(<form method="post" action="/get_pcap"><input type="submit" value="下载 PCAP"></form>)";
    response += R"(<form method="post" action="/resetcap"><input class="red" type="submit" value="清空抓取结果"></form>)";
  }
  response += R"(
    </div></div>

    <h2>运行状态</h2>
    <table>
      <tr><th>项目</th><th>当前值</th></tr>
  )";
  response += "<tr><td>断网攻击状态</td><td>" + String(isDeauthing ? "运行中" : "已停止") + "</td></tr>";
  response += "<tr><td>已发送攻击帧数</td><td>" + String(sent_frames) + "</td></tr>";
  response += "<tr><td>发送间隔延时(毫秒)</td><td>" + String(send_delay) + "</td></tr>";
  response += "<tr><td>每次发送帧数</td><td>" + String(frames_per_deauth) + "</td></tr>";
  response += "</table>";

  response += R"(
    <h2>攻击参数设置</h2>
    <div class="right"><div class="button-double">
      <form method="post" action="/setframes"><div class="button-container">
        <input class="longInput" type="text" name="frames" placeholder="每次发送帧数">
        <input type="submit" value="设置帧数">
      </div></form>
      <form method="post" action="/setdelay"><div class="button-container">
        <input class="longInput" type="text" name="delay" placeholder="发送间隔（毫秒）">
        <input type="submit" value="设置延时">
      </div></form>
    </div></div>
  </div>
  </body>
  </html>
  )";

  client.write(response.c_str());
}

#endif  // WEBPAGE_H

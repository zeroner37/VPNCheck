# VPNCheck

当前版本：`0.1`

VPNCheck 是一个专门面向 AI 服务链路的 Windows 检测工具。它用于判断当前代理节点访问 ChatGPT、OpenAI API、Claude、Gemini 等 AI 桌面应用、网页版和 API 服务时，链路是否真实稳定。

它不是通用网页测速器，也不是 VPN 客户端。VPNCheck 关注的是“普通网页能打开，但 AI 服务仍然超时、掉线、验证频繁或不可用”这一类更具体的问题。

## 为什么需要 VPNCheck

传统检测常常只能回答“网络是否连通”，却无法回答“当前线路是否适合 AI 服务”：

- `ping 1.1.1.1` 很低，不代表 ChatGPT 或 Claude 的 HTTPS 链路稳定。
- 普通测速网站使用就近 CDN，无法反映访问海外 AI 服务的真实路由和代理节点质量。
- 同一节点可能可以浏览网页，但对某个 AI 域名持续超时、抖动或选择性失败。
- AI 服务对出口 IP 类型和信誉更敏感，仅看带宽或 Ping 无法发现代理、机房、滥用等风险信号。
- 多个 AI 平台的可用性可能不同，只检测单一公共地址容易得到“看起来正常”的错误结论。

VPNCheck 直接探测配置的 AI HTTPS 端点，并结合当前 Clash/Mihomo 实际节点和出口 IP 风险信号，让结果更贴近 AI 对话、桌面客户端、网页端和 API 调用的实际体验。

## 功能

- 252×126 原生 Win32/GDI 半透明悬浮窗，无 GUI 框架依赖
- 自动识别 Clash/Mihomo 当前实际节点
- 并行探测 OpenAI API、ChatGPT 网页版、Claude 和 Gemini
- Clash 不可用时回退到多目标 ICMP 探测
- 显示延迟、抖动、丢包和 0–100 出口综合风险
- ProxyCheck 与 IPAPI 双数据源；可选 IPQualityScore、AbuseIPDB
- 风控默认每 15 分钟复查，出口 IP 变化时立即复查且不弹窗
- 自绘右键菜单、鼠标穿透、全局 `Ctrl+Alt+V`、开机启动
- 所有配置和日志仅保存在本机

## 产品边界

VPNCheck 专注于 AI 服务链路诊断：

- 适用于 AI 桌面客户端、AI 网页版、开发者 API 和依赖 AI 域名的本地工具。
- 展示 AI HTTPS 端点的延迟、抖动、失败比例，以及出口 IP 的参考风险。
- 不测试下载带宽、视频播放、游戏延迟或所有普通网站的综合浏览体验。
- 不提供代理节点、VPN 连接或绕过访问限制的功能。

## 快速开始

需要 Windows 10/11 和 Python 3.10+。运行时仅使用 Python 标准库。

```powershell
git clone https://github.com/zeroner37/VPNCheck.git
cd VPNCheck
python vpncheck.py
```

也可以双击 `run-debug.bat`。首次运行会在 `%APPDATA%\VPNCheck\config.json` 创建本地配置。

构建单文件 EXE：

```powershell
.\build.ps1
```

产物位于 `dist\VPNCheck.exe`。

## 探测原理

Clash 模式通过 Mihomo 命名管道 `\\.\pipe\verge-mihomo` 获取当前代理组和最终节点，再调用节点延迟接口访问配置中的 AI HTTPS 端点。

- 延迟：当前一轮成功端点延迟的中位数
- 抖动：相邻轮次延迟中位数之差的平均值
- 丢包：统计窗口内失败端点占全部端点请求的比例

这些数值反映经当前代理节点访问 AI 平台的链路表现，不等同于纯 ICMP RTT，也不用于评价通用网页浏览速度。

## 出口风控

| 数据源 | 用途 |
| --- | --- |
| ipify | 获取公网出口 IP |
| ipwho.is | 国家、地区、ASN、ISP |
| ProxyCheck | 代理/VPN 类型和原始风险分 |
| IPAPI | 代理、VPN、Tor、机房和滥用标签 |
| IPQualityScore | 可选的原始欺诈分，需要 API Key |
| AbuseIPDB | 可选的滥用置信分，需要 API Key |

“综合”对可用的数值信号取中位数，以降低单一数据库异常值的影响。第三方结果可能延迟或误报，不能视为任何 AI 平台的封禁结论。

## 配置

配置和日志保存在：

```text
%APPDATA%\VPNCheck\config.json
%APPDATA%\VPNCheck\vpncheck.log
```

字段示例见 [`config.example.json`](config.example.json)。请勿提交真实 API Key。鼠标穿透开启后，可按 `Ctrl+Alt+V` 恢复窗口操作。

## 开发

```powershell
python -m pip install ruff
python -m ruff check .
python -m ruff format --check .
python -m unittest discover -s tests -v
```

项目 CI 在 Windows + Python 3.12 上执行相同检查。贡献说明见 [`CONTRIBUTING.md`](CONTRIBUTING.md)，安全问题见 [`SECURITY.md`](SECURITY.md)。

## 参与项目

欢迎提交 Issue、参与 Discussion、改进文档、修改代码或提出新功能建议。无论是错误报告、界面优化、检测策略还是新的数据源想法，都欢迎一起讨论。

本项目将长期维护。后续计划会根据社区反馈持续改进检测可靠性、资源占用、可配置性和 Windows 使用体验。

## 隐私

VPNCheck 不收集或上传统计历史。为了获取出口和风险信息，程序会把当前公网 IP 发送给上表中的 IP 情报服务；链路探测会访问配置的测试端点。使用前请自行确认第三方服务条款和额度。

## License

[MIT](LICENSE)

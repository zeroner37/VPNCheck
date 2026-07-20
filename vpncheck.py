"""VPNCheck native Windows monitor for AI service connection quality.

This entry point uses only Win32/GDI through ctypes, so the packaged EXE has no
GUI framework dependency.  Network quality and risk logic is self-contained.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import ipaddress
import json
import os
import re
import statistics
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
import winreg
from collections import deque
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

APP_NAME = "VPNCheck"
APP_VERSION = "0.1"
APP_DIR = Path(os.environ.get("APPDATA", Path.home())) / APP_NAME
CONFIG_PATH = APP_DIR / "config.json"
LOG_PATH = APP_DIR / "vpncheck.log"
USER_AGENT = f"VPNCheck/{APP_VERSION} (+local desktop monitor)"


def rgb(hex_color: str) -> int:
    value = hex_color.lstrip("#")
    r, g, b = (int(value[i : i + 2], 16) for i in (0, 2, 4))
    return r | (g << 8) | (b << 16)


def clamp(value: float, minimum: float, maximum: float) -> float:
    return max(minimum, min(maximum, value))


def log(message: str) -> None:
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except OSError:
        pass


@dataclass
class Settings:
    ping_target: str = "1.1.1.1"
    ping_interval: float = 1.0
    ping_timeout_ms: int = 1200
    sample_size: int = 60
    ip_check_interval: int = 60
    risk_refresh_interval: int = 900
    opacity: float = 0.94
    always_on_top: bool = True
    click_through: bool = False
    auto_start: bool = False
    proxycheck_api_key: str = ""
    ipqs_api_key: str = ""
    abuseipdb_api_key: str = ""
    alert_on_ip_change: bool = False
    clash_auto_detect: bool = True
    clash_pipe: str = r"\\.\pipe\verge-mihomo"
    clash_group: str = ""
    clash_delay_url: str = "https://www.gstatic.com/generate_204"
    ping_targets: list[str] | None = None
    ai_probe_interval: float = 5.0
    ai_probe_targets: list[dict[str, str]] | None = None
    x: int | None = None
    y: int | None = None

    @classmethod
    def load(cls) -> "Settings":
        APP_DIR.mkdir(parents=True, exist_ok=True)
        if CONFIG_PATH.exists():
            try:
                raw = json.loads(CONFIG_PATH.read_text(encoding="utf-8-sig"))
                names = {item.name for item in fields(cls)}
                return cls(**{k: v for k, v in raw.items() if k in names})
            except Exception as exc:
                log(f"config load failed: {exc}")
        value = cls()
        value.save()
        return value

    def normalize(self) -> None:
        self.ping_interval = clamp(float(self.ping_interval), 0.25, 60)
        self.ping_timeout_ms = int(clamp(int(self.ping_timeout_ms), 200, 10000))
        self.sample_size = int(clamp(int(self.sample_size), 10, 600))
        self.ip_check_interval = int(clamp(int(self.ip_check_interval), 15, 3600))
        self.risk_refresh_interval = int(clamp(int(self.risk_refresh_interval), 60, 86400))
        self.opacity = clamp(float(self.opacity), 0.35, 1.0)
        target = str(self.ping_target).strip()
        self.ping_target = target if target and " " not in target else "1.1.1.1"
        if not isinstance(self.ping_targets, list) or not self.ping_targets:
            self.ping_targets = [self.ping_target, "8.8.8.8", "9.9.9.9"]
        self.ping_targets = [str(item).strip() for item in self.ping_targets if str(item).strip()][:5]
        self.alert_on_ip_change = False
        self.ai_probe_interval = clamp(float(self.ai_probe_interval), 2.0, 60.0)
        if not isinstance(self.ai_probe_targets, list) or not self.ai_probe_targets:
            self.ai_probe_targets = [
                {"name": "OpenAI", "url": "https://api.openai.com/favicon.ico"},
                {"name": "ChatGPT", "url": "https://chatgpt.com/favicon.ico"},
                {"name": "Claude", "url": "https://claude.ai/favicon.ico"},
                {"name": "Gemini", "url": "https://gemini.google.com/favicon.ico"},
            ]
        self.ai_probe_targets = [
            {"name": str(item.get("name", "AI"))[:20], "url": str(item.get("url", ""))}
            for item in self.ai_probe_targets
            if isinstance(item, dict) and str(item.get("url", "")).startswith("https://")
        ][:8]

    def save(self) -> None:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(asdict(self), ensure_ascii=False, indent=2), encoding="utf-8")


@dataclass
class RiskInfo:
    ip: str = "--"
    score: int | None = None
    proxy: bool | None = None
    vpn: bool | None = None
    risk_type: str = "未知"
    country: str = "--"
    region: str = ""
    city: str = ""
    asn: str = "--"
    isp: str = "--"
    source: str = "未查询"
    proxycheck_score: int | None = None
    ipqs_score: int | None = None
    abuse_score: int | None = None
    ipapi_flags: str = "--"
    ipapi_signal: int | None = None
    composite_score: int | None = None
    source_count: int = 0
    updated_at: float = 0.0
    error: str = ""


def parse_windows_ping(output: str) -> float | None:
    if "ttl=" not in output.lower():
        return None
    match = re.findall(r"(?:time|时间)\s*[=<]\s*(\d+)\s*ms", output, re.I)
    if match:
        return float(match[-1])
    if re.search(r"(?:time|时间)\s*<\s*1\s*ms", output, re.I):
        return 0.5
    return None


def ping_once(target: str, timeout_ms: int) -> float | None:
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    try:
        result = subprocess.run(
            ["ping", "-n", "1", "-w", str(timeout_ms), target],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(3.0, timeout_ms / 1000 + 2),
            startupinfo=startup,
            creationflags=subprocess.CREATE_NO_WINDOW,
            check=False,
        )
        return parse_windows_ping(result.stdout + result.stderr)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log(f"ping failed: {exc}")
        return None


class MetricWindow:
    def __init__(self, size: int) -> None:
        self.samples: deque[float | None] = deque(maxlen=max(10, size))

    def add(self, value: float | None) -> None:
        self.samples.append(value)

    def snapshot(self) -> dict[str, float | int | None]:
        values = list(self.samples)
        valid = [x for x in values if x is not None]
        count = len(values)
        return {
            "latest": values[-1] if values else None,
            "average": statistics.fmean(valid) if valid else None,
            "jitter": statistics.fmean(abs(b - a) for a, b in zip(valid, valid[1:])) if len(valid) > 1 else 0.0,
            "loss": ((count - len(valid)) / count * 100) if count else 0.0,
            "count": count,
        }


class MultiTargetMetricWindow:
    """Rolling per-cycle metrics for several AI endpoints.

    Latency is the median successful endpoint time in each cycle. Packet loss is
    calculated across all endpoint attempts, so one blocked AI service remains
    visible instead of being hidden by a successful fallback.
    """

    def __init__(self, size: int) -> None:
        self.cycles: deque[list[float | None]] = deque(maxlen=max(10, size))

    def add_batch(self, values: list[float | None]) -> None:
        self.cycles.append(list(values))

    def snapshot(self) -> dict[str, float | int | None]:
        cycle_values: list[float] = []
        total = 0
        failed = 0
        for cycle in self.cycles:
            valid = [value for value in cycle if value is not None]
            total += len(cycle)
            failed += len(cycle) - len(valid)
            if valid:
                cycle_values.append(float(statistics.median(valid)))
        latest_cycle = self.cycles[-1] if self.cycles else []
        latest_valid = [value for value in latest_cycle if value is not None]
        latest = float(statistics.median(latest_valid)) if latest_valid else None
        jitter = (
            statistics.fmean(abs(b - a) for a, b in zip(cycle_values, cycle_values[1:]))
            if len(cycle_values) > 1
            else 0.0
        )
        return {
            "latest": latest,
            "average": statistics.fmean(cycle_values) if cycle_values else None,
            "jitter": jitter,
            "loss": failed / total * 100 if total else 0.0,
            "count": len(self.cycles),
        }


def quality_label(metrics: dict[str, float | int | None]) -> tuple[str, str]:
    latency = metrics["average"]
    jitter = float(metrics["jitter"] or 0)
    loss = float(metrics["loss"] or 0)
    if metrics["count"] == 0:
        return "检测中", "#9CA3AF"
    if latency is None or loss >= 50:
        return "已断开", "#EF4444"
    score = 100 - clamp((float(latency) - 35) * 0.35, 0, 35) - clamp(jitter * 1.2, 0, 25) - clamp(loss * 4, 0, 50)
    if score >= 85:
        return "优秀", "#34D399"
    if score >= 70:
        return "良好", "#A3E635"
    if score >= 50:
        return "一般", "#FBBF24"
    return "较差", "#F87171"


def risk_label(score: int | None) -> tuple[str, str]:
    if score is None:
        return "未知", "#9CA3AF"
    if score <= 20:
        return "低风险", "#34D399"
    if score <= 49:
        return "注意", "#FBBF24"
    if score <= 69:
        return "高风险", "#FB923C"
    return "很高风险", "#F87171"


def http_json(url: str, timeout: float = 8.0, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def get_public_ip() -> str:
    last_error: Exception | None = None
    for endpoint in ("https://api64.ipify.org?format=json", "https://api.ipify.org?format=json"):
        try:
            value = http_json(endpoint).get("ip", "")
            ipaddress.ip_address(value)
            return value
        except Exception as exc:
            last_error = exc
    raise RuntimeError(f"无法获取出口 IP: {last_error}")


def query_risk(
    ip: str,
    proxycheck_key: str = "",
    ipqs_key: str = "",
    abuseipdb_key: str = "",
) -> RiskInfo:
    """Collect independent reputation signals and preserve raw vendor scores."""
    info = RiskInfo(ip=ip, updated_at=time.time())
    errors: list[str] = []
    vendor_scores: list[int] = []
    sources: list[str] = []

    try:
        geo = http_json(f"https://ipwho.is/{urllib.parse.quote(ip)}")
        if geo.get("success", True):
            info.country = geo.get("country") or "--"
            info.region = geo.get("region") or ""
            info.city = geo.get("city") or ""
            connection = geo.get("connection") or {}
            asn = connection.get("asn")
            info.asn = f"AS{asn}" if asn else "--"
            info.isp = connection.get("isp") or connection.get("org") or "--"
            sources.append("ipwho.is")
    except Exception as exc:
        errors.append(f"ipwho.is: {exc}")

    try:
        key = f"&key={urllib.parse.quote(proxycheck_key)}" if proxycheck_key else ""
        risk = http_json(f"https://proxycheck.io/v2/{urllib.parse.quote(ip)}?vpn=1&asn=1&risk=1{key}")
        record = risk.get(ip) or {}
        if risk.get("status") == "ok" and record:
            raw_score = record.get("risk")
            score = int(float(raw_score)) if raw_score not in (None, "") else None
            info.proxycheck_score = score
            info.proxy = str(record.get("proxy", "")).lower() == "yes"
            info.vpn = "vpn" in str(record.get("type", "")).lower()
            info.risk_type = record.get("type") or ("代理" if info.proxy else "普通网络")
            info.country = record.get("country") or info.country
            info.isp = record.get("provider") or info.isp
            info.asn = record.get("asn") or info.asn
            if score is not None:
                vendor_scores.append(score)
            sources.append("ProxyCheck")
        else:
            errors.append(f"ProxyCheck: {risk.get('message') or '无结果'}")
    except Exception as exc:
        errors.append(f"ProxyCheck: {exc}")

    try:
        ipapi = http_json(f"https://api.ipapi.is/?q={urllib.parse.quote(ip)}")
        flags: list[str] = []
        signal = 0
        for key, label, weight in (
            ("is_abuser", "滥用", 75),
            ("is_tor", "Tor", 85),
            ("is_proxy", "代理", 60),
            ("is_vpn", "VPN", 45),
            ("is_datacenter", "机房", 45),
        ):
            if ipapi.get(key):
                flags.append(label)
                signal = max(signal, weight)
        info.ipapi_flags = "/".join(flags) if flags else "清洁"
        info.ipapi_signal = signal
        sources.append("IPAPI")
    except Exception as exc:
        errors.append(f"IPAPI: {exc}")

    if ipqs_key:
        try:
            ipqs = http_json(
                f"https://www.ipqualityscore.com/api/json/ip/{urllib.parse.quote(ipqs_key)}/{urllib.parse.quote(ip)}?strictness=1&allow_public_access_points=true"
            )
            if ipqs.get("success", True) and ipqs.get("fraud_score") is not None:
                info.ipqs_score = int(ipqs["fraud_score"])
                vendor_scores.append(info.ipqs_score)
                sources.append("IPQS")
            else:
                errors.append(f"IPQS: {ipqs.get('message') or '无结果'}")
        except Exception as exc:
            errors.append(f"IPQS: {exc}")

    if abuseipdb_key:
        try:
            abuse = http_json(
                f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90",
                extra_headers={"Key": abuseipdb_key},
            )
            value = (abuse.get("data") or {}).get("abuseConfidenceScore")
            if value is not None:
                info.abuse_score = int(value)
                vendor_scores.append(info.abuse_score)
                sources.append("AbuseIPDB")
            else:
                errors.append("AbuseIPDB: 无结果")
        except Exception as exc:
            errors.append(f"AbuseIPDB: {exc}")

    if vendor_scores:
        combined = list(vendor_scores)
        if info.ipapi_signal is not None:
            combined.append(info.ipapi_signal)
        info.composite_score = int(round(statistics.median(combined)))
        info.score = info.composite_score
    elif info.ipapi_signal:
        # A positive independent flag is useful alone; a lone "clean" flag is
        # not sufficient evidence to claim a definitive zero-risk score.
        info.composite_score = info.ipapi_signal
        info.score = info.composite_score
    info.source_count = len([name for name in sources if name != "ipwho.is"])
    info.source = " + ".join(sources) if sources else "未查询"
    info.error = "; ".join(errors)
    return info


def clash_pipe_request(pipe: str, path: str) -> dict[str, Any]:
    """Issue a read-only HTTP request to Mihomo over a Windows named pipe."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateFileW.restype = wt.HANDLE
    kernel.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
    kernel.WriteFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
    kernel.ReadFile.argtypes = [wt.HANDLE, ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
    kernel.CloseHandle.argtypes = [wt.HANDLE]
    handle = kernel.CreateFileW(pipe, 0x80000000 | 0x40000000, 0, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        request = f"GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode()
        written = wt.DWORD()
        if not kernel.WriteFile(handle, request, len(request), ctypes.byref(written), None):
            raise ctypes.WinError(ctypes.get_last_error())
        chunks: list[bytes] = []
        while True:
            buffer = ctypes.create_string_buffer(65536)
            count = wt.DWORD()
            ok = kernel.ReadFile(handle, buffer, len(buffer), ctypes.byref(count), None)
            if count.value:
                chunks.append(buffer.raw[: count.value])
            if not ok:
                error = ctypes.get_last_error()
                if error == 234:  # ERROR_MORE_DATA
                    continue
                if error in (109, 232, 233):
                    break
                raise ctypes.WinError(error)
            if not count.value:
                break
        response = b"".join(chunks)
        head, separator, body = response.partition(b"\r\n\r\n")
        if not separator or not head.startswith(b"HTTP/1.1 200"):
            status = head.split(b"\r\n", 1)[0].decode(errors="replace")
            raise RuntimeError(f"Mihomo API {status or '无响应'}")
        if b"transfer-encoding: chunked" in head.lower():
            decoded = bytearray()
            while body:
                line, _, body = body.partition(b"\r\n")
                size = int(line.split(b";", 1)[0], 16)
                if not size:
                    break
                decoded += body[:size]
                body = body[size + 2 :]
            body = bytes(decoded)
        return json.loads(body)
    finally:
        kernel.CloseHandle(handle)


def clash_current_node(pipe: str, preferred_group: str = "") -> tuple[str, str]:
    proxies = clash_pipe_request(pipe, "/proxies").get("proxies", {})
    if not isinstance(proxies, dict):
        raise RuntimeError("Mihomo 未返回代理列表")
    candidates: list[tuple[str, dict[str, Any]]] = []
    if preferred_group and isinstance(proxies.get(preferred_group), dict):
        candidates.append((preferred_group, proxies[preferred_group]))
    candidates.extend(
        (name, value)
        for name, value in proxies.items()
        if isinstance(value, dict) and value.get("now") and name != "GLOBAL" and (name, value) not in candidates
    )
    group_name = ""
    selected = ""
    for wanted_type in ("Selector", "URLTest", "Fallback", "LoadBalance"):
        match = next(
            (
                (name, value)
                for name, value in candidates
                if value.get("type") == wanted_type and value.get("now") not in ("DIRECT", "REJECT")
            ),
            None,
        )
        if match:
            group_name, selected = match[0], str(match[1].get("now") or "")
            break
    if not selected and candidates:
        group_name, selected = candidates[0][0], str(candidates[0][1].get("now") or "")
    seen: set[str] = set()
    while selected and selected not in seen:
        seen.add(selected)
        item = proxies.get(selected)
        if not isinstance(item, dict) or not item.get("now"):
            break
        selected = str(item["now"])
    if not selected:
        raise RuntimeError("未找到当前 Clash 节点")
    return group_name, selected


def clash_node_delay(pipe: str, node: str, url: str, timeout_ms: int) -> float | None:
    path = "/proxies/{}/delay?timeout={}&url={}".format(
        urllib.parse.quote(node, safe=""),
        max(1000, timeout_ms),
        urllib.parse.quote(url, safe=""),
    )
    value = clash_pipe_request(pipe, path).get("delay")
    return float(value) if isinstance(value, (int, float)) and value > 0 else None


# Win32 constants
WM_DESTROY, WM_PAINT = 0x0002, 0x000F
WM_KILLFOCUS, WM_MOUSEMOVE, WM_LBUTTONDOWN, WM_LBUTTONUP, WM_RBUTTONUP, WM_HOTKEY = (
    0x0008,
    0x0200,
    0x0201,
    0x0202,
    0x0205,
    0x0312,
)
WM_APP_UPDATE = 0x8001
WS_POPUP = 0x80000000
WS_EX_LAYERED, WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT = 0x00080000, 0x00000080, 0x00000008, 0x00000020
LWA_ALPHA = 0x00000002
SW_SHOWNORMAL, SW_SHOWNOACTIVATE = 1, 4
SWP_NOSIZE, SWP_NOACTIVATE = 0x0001, 0x0010
HWND_TOPMOST, HWND_NOTOPMOST = -1, -2
DT_LEFT, DT_RIGHT, DT_SINGLELINE, DT_VCENTER, DT_END_ELLIPSIS = 0x0000, 0x0002, 0x0020, 0x0004, 0x00008000
TRANSPARENT = 1
MOD_ALT, MOD_CONTROL, MOD_NOREPEAT = 0x0001, 0x0002, 0x4000
VK_V = 0x56
HTCAPTION, WM_NCLBUTTONDOWN = 2, 0x00A1
ID_REFRESH, ID_CLICK, ID_RESET, ID_CONFIG, ID_STARTUP, ID_ABOUT, ID_DETAILS, ID_EXIT = (
    1001,
    1002,
    1003,
    1004,
    1005,
    1006,
    1007,
    1099,
)

user32, gdi32, kernel32 = ctypes.windll.user32, ctypes.windll.gdi32, ctypes.windll.kernel32
user32.CreateWindowExW.restype = wt.HWND
user32.DefWindowProcW.restype = ctypes.c_ssize_t
WNDPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, wt.HWND, wt.UINT, wt.WPARAM, wt.LPARAM)


class WNDCLASSW(ctypes.Structure):
    _fields_ = [
        ("style", wt.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wt.HINSTANCE),
        ("hIcon", wt.HICON),
        ("hCursor", wt.HANDLE),
        ("hbrBackground", wt.HBRUSH),
        ("lpszMenuName", wt.LPCWSTR),
        ("lpszClassName", wt.LPCWSTR),
    ]


class PAINTSTRUCT(ctypes.Structure):
    _fields_ = [
        ("hdc", wt.HDC),
        ("fErase", wt.BOOL),
        ("rcPaint", wt.RECT),
        ("fRestore", wt.BOOL),
        ("fIncUpdate", wt.BOOL),
        ("rgbReserved", ctypes.c_byte * 32),
    ]


class NativeApp:
    WIDTH, HEIGHT, MENU_WIDTH = 252, 126, 244
    BG, PANEL, TEXT, MUTED, BLUE = "#10151E", "#18202C", "#F3F4F6", "#94A3B8", "#60A5FA"

    def __init__(self) -> None:
        self.settings = Settings.load()
        self.settings.normalize()
        self.settings.save()
        self.metrics = MultiTargetMetricWindow(self.settings.sample_size)
        self.risk = RiskInfo()
        self.last_ip = ""
        self.clash_group = ""
        self.clash_node = ""
        self.link_source = "ICMP"
        self.clash_last_discovery = 0.0
        self.risk_busy = False
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.hwnd: int = 0
        self.menu_hwnd: int = 0
        self.menu_hover = -1
        self.menu_items = [
            (ID_REFRESH, "立即刷新出口与风控"),
            (ID_DETAILS, "完整节点与风控详情"),
            (0, ""),
            (ID_CLICK, "鼠标穿透  Ctrl+Alt+V"),
            (ID_RESET, "恢复到右下角"),
            (ID_CONFIG, "打开设置文件（保存后重启）"),
            (ID_STARTUP, "开机启动"),
            (0, ""),
            (ID_ABOUT, "关于"),
            (ID_EXIT, "退出"),
        ]
        self._callback = WNDPROC(self._wnd_proc)
        self._fonts: list[int] = []
        self.font_title = self._font(14, 600, "Segoe UI")
        self.font_body = self._font(12, 400, "Microsoft YaHei UI")
        self.font_small = self._font(10, 400, "Microsoft YaHei UI")
        self.font_metric = self._font(18, 600, "Segoe UI")
        self.font_unit = self._font(10, 400, "Segoe UI")
        self._create_window()
        self._set_autostart(self.settings.auto_start)

    def _font(self, size: int, weight: int, face: str) -> int:
        font = gdi32.CreateFontW(-size, 0, 0, 0, weight, 0, 0, 0, 1, 0, 0, 5, 0, face)
        self._fonts.append(font)
        return font

    def _create_window(self) -> None:
        instance = kernel32.GetModuleHandleW(None)
        class_name = "VPNCheckNativeWindow"
        self.instance = instance
        self.class_name = class_name
        wc = WNDCLASSW()
        wc.lpfnWndProc, wc.hInstance, wc.lpszClassName = self._callback, instance, class_name
        wc.hCursor = user32.LoadCursorW(None, 32512)
        wc.hbrBackground = gdi32.CreateSolidBrush(rgb(self.BG))
        if not user32.RegisterClassW(ctypes.byref(wc)) and ctypes.get_last_error() != 1410:
            raise ctypes.WinError()
        x, y = self._default_position()
        exstyle = WS_EX_LAYERED | WS_EX_TOOLWINDOW | (WS_EX_TOPMOST if self.settings.always_on_top else 0)
        if self.settings.click_through:
            exstyle |= WS_EX_TRANSPARENT
        self.hwnd = user32.CreateWindowExW(
            exstyle,
            class_name,
            f"{APP_NAME} {APP_VERSION}",
            WS_POPUP,
            x,
            y,
            self.WIDTH,
            self.HEIGHT,
            None,
            None,
            instance,
            None,
        )
        if not self.hwnd:
            raise ctypes.WinError()
        user32.SetLayeredWindowAttributes(self.hwnd, 0, int(self.settings.opacity * 255), LWA_ALPHA)
        region = gdi32.CreateRoundRectRgn(0, 0, self.WIDTH + 1, self.HEIGHT + 1, 14, 14)
        user32.SetWindowRgn(self.hwnd, region, True)
        user32.RegisterHotKey(self.hwnd, 1, MOD_ALT | MOD_CONTROL | MOD_NOREPEAT, VK_V)
        user32.ShowWindow(self.hwnd, SW_SHOWNOACTIVATE)
        user32.UpdateWindow(self.hwnd)

    def _default_position(self) -> tuple[int, int]:
        if self.settings.x is not None and self.settings.y is not None:
            return int(self.settings.x), int(self.settings.y)
        work = wt.RECT()
        user32.SystemParametersInfoW(48, 0, ctypes.byref(work), 0)
        return work.right - self.WIDTH - 16, work.bottom - self.HEIGHT - 16

    def _wnd_proc(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        if self.menu_hwnd and hwnd == self.menu_hwnd:
            return self._menu_wnd_proc(hwnd, msg, wparam, lparam)
        if msg == WM_PAINT:
            self._paint(hwnd)
            return 0
        if msg == WM_LBUTTONDOWN and not self.settings.click_through:
            if self._close_hit(lparam):
                return 0
            user32.ReleaseCapture()
            user32.SendMessageW(hwnd, WM_NCLBUTTONDOWN, HTCAPTION, 0)
            return 0
        if msg == WM_LBUTTONUP and not self.settings.click_through:
            if self._close_hit(lparam):
                user32.DestroyWindow(self.hwnd)
            return 0
        if msg == WM_RBUTTONUP and not self.settings.click_through:
            self._show_custom_menu()
            return 0
        if msg == WM_HOTKEY:
            self.toggle_click_through()
            return 0
        if msg == WM_APP_UPDATE:
            user32.InvalidateRect(hwnd, None, False)
            return 0
        if msg == WM_DESTROY:
            rect = wt.RECT()
            if user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                self.settings.x, self.settings.y = rect.left, rect.top
                self.settings.save()
            self.stop.set()
            user32.UnregisterHotKey(hwnd, 1)
            user32.PostQuitMessage(0)
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _close_hit(self, lparam: int) -> bool:
        x, y = lparam & 0xFFFF, (lparam >> 16) & 0xFFFF
        return self.WIDTH - 22 <= x < self.WIDTH - 4 and 4 <= y < 23

    def _text(
        self,
        hdc: int,
        text: str,
        rect: tuple[int, int, int, int],
        font: int,
        color: str,
        flags: int = DT_LEFT | DT_SINGLELINE | DT_VCENTER,
    ) -> None:
        old = gdi32.SelectObject(hdc, font)
        gdi32.SetTextColor(hdc, rgb(color))
        gdi32.SetBkMode(hdc, TRANSPARENT)
        rc = wt.RECT(*rect)
        user32.DrawTextW(hdc, str(text), -1, ctypes.byref(rc), flags | DT_END_ELLIPSIS)
        gdi32.SelectObject(hdc, old)

    def _paint(self, hwnd: int) -> None:
        ps = PAINTSTRUCT()
        hdc = user32.BeginPaint(hwnd, ctypes.byref(ps))
        try:
            rect = wt.RECT(0, 0, self.WIDTH, self.HEIGHT)
            bg = gdi32.CreateSolidBrush(rgb(self.BG))
            user32.FillRect(hdc, ctypes.byref(rect), bg)
            gdi32.DeleteObject(bg)
            panel_rect = wt.RECT(8, 8, self.WIDTH - 8, 65)
            panel = gdi32.CreateSolidBrush(rgb(self.PANEL))
            user32.FillRect(hdc, ctypes.byref(panel_rect), panel)
            gdi32.DeleteObject(panel)
            with self.lock:
                metrics = self.metrics.snapshot()
                risk = self.risk
            quality, quality_color = quality_label(metrics)
            risk_name, risk_color = risk_label(risk.score)
            labels = (("延迟", 12), ("抖动", 88), ("丢包", 166))
            for label, x in labels:
                self._text(hdc, label, (x, 9, x + 44, 29), self.font_small, self.MUTED)
            latest = metrics["latest"]
            latency = (
                "超时" if metrics["count"] and latest is None else (f"{latest:.0f}" if latest is not None else "--")
            )
            self._text(hdc, latency, (12, 27, 53, 61), self.font_metric, quality_color)
            if latency not in ("超时", "--"):
                self._text(hdc, "ms", (52, 34, 77, 60), self.font_unit, self.MUTED)
            self._text(hdc, f"{float(metrics['jitter'] or 0):.1f}", (88, 27, 135, 61), self.font_metric, self.TEXT)
            self._text(hdc, "ms", (133, 34, 158, 60), self.font_unit, self.MUTED)
            self._text(hdc, f"{float(metrics['loss'] or 0):.1f}", (166, 27, 210, 61), self.font_metric, self.TEXT)
            self._text(hdc, "%", (209, 34, 232, 60), self.font_unit, self.MUTED)
            self._text(hdc, "综合", (12, 68, 48, 94), self.font_body, self.MUTED)
            score = "--" if risk.score is None else str(risk.score)
            self._text(hdc, score, (48, 67, 78, 94), self.font_title, self.TEXT)
            self._text(hdc, "/100", (77, 70, 112, 94), self.font_unit, self.MUTED)
            source_suffix = f" {risk.source_count}源" if risk.source_count else ""
            self._text(
                hdc,
                f"● {risk_name}{source_suffix}",
                (120, 67, 240, 94),
                self.font_body,
                risk_color,
                DT_RIGHT | DT_SINGLELINE | DT_VCENTER,
            )
            node_text = self.clash_node or "检测中…"
            self._text(hdc, f"节点  {node_text}", (12, 96, 240, 122), self.font_small, self.MUTED)
            self._text(
                hdc,
                "×",
                (self.WIDTH - 22, 4, self.WIDTH - 4, 23),
                self.font_title,
                "#F87171",
                DT_RIGHT | DT_SINGLELINE | DT_VCENTER,
            )
        finally:
            user32.EndPaint(hwnd, ctypes.byref(ps))

    def _menu_layout(self) -> tuple[list[tuple[int, int, int, str]], int]:
        rows: list[tuple[int, int, int, str]] = []
        y = 6
        for command, label in self.menu_items:
            height = 9 if command == 0 else 28
            rows.append((y, y + height, command, label))
            y += height
        return rows, y + 6

    def _show_custom_menu(self) -> None:
        if self.menu_hwnd and user32.IsWindow(self.menu_hwnd):
            user32.DestroyWindow(self.menu_hwnd)
        self.menu_hwnd = 0
        self.menu_hover = -1
        menu_width = self.MENU_WIDTH
        _, menu_height = self._menu_layout()
        point = wt.POINT()
        work = wt.RECT()
        user32.GetCursorPos(ctypes.byref(point))
        user32.SystemParametersInfoW(48, 0, ctypes.byref(work), 0)
        x = min(max(point.x, work.left), work.right - menu_width)
        y = min(max(point.y, work.top), work.bottom - menu_height)
        hwnd = user32.CreateWindowExW(
            WS_EX_TOOLWINDOW | WS_EX_TOPMOST,
            self.class_name,
            "VPNCheckMenu",
            WS_POPUP,
            x,
            y,
            menu_width,
            menu_height,
            self.hwnd,
            None,
            self.instance,
            None,
        )
        if not hwnd:
            log(f"custom menu creation failed: {ctypes.get_last_error()}")
            return
        self.menu_hwnd = hwnd
        region = gdi32.CreateRoundRectRgn(0, 0, menu_width + 1, menu_height + 1, 10, 10)
        user32.SetWindowRgn(hwnd, region, True)
        user32.ShowWindow(hwnd, SW_SHOWNORMAL)
        user32.SetForegroundWindow(hwnd)
        user32.UpdateWindow(hwnd)

    def _menu_command_at(self, y: int) -> tuple[int, int]:
        for index, (top, bottom, command, _label) in enumerate(self._menu_layout()[0]):
            if top <= y < bottom and command:
                return index, command
        return -1, 0

    def _menu_wnd_proc(self, hwnd: int, msg: int, wparam: int, lparam: int) -> int:
        if msg == WM_PAINT:
            self._paint_custom_menu(hwnd)
            return 0
        if msg == WM_MOUSEMOVE:
            index, _ = self._menu_command_at((lparam >> 16) & 0xFFFF)
            if index != self.menu_hover:
                self.menu_hover = index
                user32.InvalidateRect(hwnd, None, False)
            return 0
        if msg == WM_LBUTTONUP:
            _, command = self._menu_command_at((lparam >> 16) & 0xFFFF)
            user32.DestroyWindow(hwnd)
            if command:
                self._command(command)
            return 0
        if msg == WM_KILLFOCUS:
            user32.DestroyWindow(hwnd)
            return 0
        if msg == WM_DESTROY:
            if hwnd == self.menu_hwnd:
                self.menu_hwnd = 0
                self.menu_hover = -1
            return 0
        return user32.DefWindowProcW(hwnd, msg, wparam, lparam)

    def _paint_custom_menu(self, hwnd: int) -> None:
        ps = PAINTSTRUCT()
        hdc = user32.BeginPaint(hwnd, ctypes.byref(ps))
        try:
            _rows, menu_height = self._menu_layout()
            background = gdi32.CreateSolidBrush(rgb("#151C27"))
            rect = wt.RECT(0, 0, self.MENU_WIDTH, menu_height)
            user32.FillRect(hdc, ctypes.byref(rect), background)
            gdi32.DeleteObject(background)
            for index, (top, bottom, command, label) in enumerate(self._menu_layout()[0]):
                if not command:
                    separator = gdi32.CreateSolidBrush(rgb("#334155"))
                    line = wt.RECT(12, top + 4, self.MENU_WIDTH - 12, top + 5)
                    user32.FillRect(hdc, ctypes.byref(line), separator)
                    gdi32.DeleteObject(separator)
                    continue
                if index == self.menu_hover:
                    highlight = gdi32.CreateSolidBrush(rgb("#263449"))
                    row_rect = wt.RECT(5, top, self.MENU_WIDTH - 5, bottom)
                    user32.FillRect(hdc, ctypes.byref(row_rect), highlight)
                    gdi32.DeleteObject(highlight)
                checked = (command == ID_CLICK and self.settings.click_through) or (
                    command == ID_STARTUP and self.settings.auto_start
                )
                prefix = "✓  " if checked else "    "
                self._text(hdc, prefix + label, (14, top, self.MENU_WIDTH - 12, bottom), self.font_body, self.TEXT)
        finally:
            user32.EndPaint(hwnd, ctypes.byref(ps))

    def _command(self, command: int) -> None:
        if command == ID_REFRESH:
            threading.Thread(target=lambda: self._refresh_risk(force=True), daemon=True).start()
        elif command == ID_CLICK:
            self.toggle_click_through()
        elif command == ID_RESET:
            x, y = self._default_position_for_reset()
            user32.SetWindowPos(
                self.hwnd,
                HWND_TOPMOST if self.settings.always_on_top else HWND_NOTOPMOST,
                x,
                y,
                0,
                0,
                SWP_NOSIZE | SWP_NOACTIVATE,
            )
            self.settings.x, self.settings.y = x, y
            self.settings.save()
        elif command == ID_CONFIG:
            self.settings.save()
            os.startfile(CONFIG_PATH)
        elif command == ID_STARTUP:
            self.settings.auto_start = not self.settings.auto_start
            self._set_autostart(self.settings.auto_start)
            self.settings.save()
        elif command == ID_DETAILS:
            with self.lock:
                risk = self.risk
                ip = self.last_ip or "获取中…"
            vendor_lines = [
                f"ProxyCheck：{risk.proxycheck_score if risk.proxycheck_score is not None else '--'}",
                f"IPAPI：{risk.ipapi_flags}",
            ]
            if risk.ipqs_score is not None:
                vendor_lines.append(f"IPQualityScore：{risk.ipqs_score}")
            if risk.abuse_score is not None:
                vendor_lines.append(f"AbuseIPDB：{risk.abuse_score}")
            location = " ".join(item for item in (risk.country, risk.region, risk.city) if item and item != "--")
            last_check = time.strftime("%H:%M:%S", time.localtime(risk.updated_at)) if risk.updated_at else "--"
            next_check = (
                time.strftime("%H:%M:%S", time.localtime(risk.updated_at + self.settings.risk_refresh_interval))
                if risk.updated_at
                else "--"
            )
            ai_names = "/".join(item["name"] for item in (self.settings.ai_probe_targets or []))
            text = (
                f"出口 IP：{ip}\n"
                f"当前节点：{self.clash_node or '--'}\n"
                f"AI 探测：{ai_names}\n"
                f"链路来源：{self.link_source}\n\n"
                f"综合：{risk.score if risk.score is not None else '--'} / 100\n"
                + "\n".join(vendor_lines)
                + f"\n\n位置：{location or '--'}\nASN：{risk.asn}\nISP：{risk.isp}\n"
                + f"数据源：{risk.source}\n"
                + f"上次风控：{last_check}　下次约：{next_check}\n\n"
                + "综合值为各数值信号的中位数；IPAPI 标签会转换为明确标注的本地风险信号。"
            )
            user32.MessageBoxW(self.hwnd, text, "完整详情", 0x40)
        elif command == ID_ABOUT:
            user32.MessageBoxW(
                self.hwnd,
                f"VPNCheck {APP_VERSION}\n\n面向 ChatGPT、Claude、Gemini 和 AI API 的专用链路检测工具。\n检测 AI HTTPS 延迟、抖动、失败比例与出口 IP 参考风险。\n不是通用网页测速器或 VPN 客户端。\n\nCtrl+Alt+V：切换鼠标穿透",
                "关于 VPNCheck",
                0x40,
            )
        elif command == ID_EXIT:
            user32.DestroyWindow(self.hwnd)

    def _default_position_for_reset(self) -> tuple[int, int]:
        work = wt.RECT()
        user32.SystemParametersInfoW(48, 0, ctypes.byref(work), 0)
        return work.right - self.WIDTH - 16, work.bottom - self.HEIGHT - 16

    def toggle_click_through(self) -> None:
        self.settings.click_through = not self.settings.click_through
        style = user32.GetWindowLongW(self.hwnd, -20)
        style = (style | WS_EX_TRANSPARENT) if self.settings.click_through else (style & ~WS_EX_TRANSPARENT)
        user32.SetWindowLongW(self.hwnd, -20, style)
        self.settings.save()

    def _set_autostart(self, enabled: bool) -> None:
        try:
            with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE
            ) as key:
                if enabled:
                    executable = sys.executable if getattr(sys, "frozen", False) else Path(__file__).resolve()
                    winreg.SetValueEx(key, APP_NAME, 0, winreg.REG_SZ, f'"{executable}"')
                else:
                    try:
                        winreg.DeleteValue(key, APP_NAME)
                    except FileNotFoundError:
                        pass
        except OSError as exc:
            log(f"autostart failed: {exc}")
            user32.MessageBoxW(self.hwnd, f"无法修改开机启动：\n{exc}", APP_NAME, 0x30)

    def _probe_ai_targets(self, targets: list[dict[str, str]]) -> list[float | None]:
        """Probe with at most two short-lived workers to limit thread stack memory."""
        results: list[float | None] = [None] * len(targets)

        def worker(offset: int, stride: int) -> None:
            for index in range(offset, len(targets), stride):
                try:
                    results[index] = clash_node_delay(
                        self.settings.clash_pipe,
                        self.clash_node,
                        targets[index]["url"],
                        max(6000, self.settings.ping_timeout_ms),
                    )
                except Exception as exc:
                    log(f"AI endpoint probe failed: {exc}")

        worker_count = min(2, len(targets))
        workers = [
            threading.Thread(target=worker, args=(index, worker_count), daemon=True) for index in range(worker_count)
        ]
        for thread in workers:
            thread.start()
        for thread in workers:
            thread.join()
        return results

    def _ping_loop(self) -> None:
        while not self.stop.is_set():
            started = time.monotonic()
            values: list[float | None] = []
            if self.settings.clash_auto_detect:
                try:
                    if not self.clash_node or time.monotonic() - self.clash_last_discovery >= 5:
                        self.clash_group, self.clash_node = clash_current_node(
                            self.settings.clash_pipe, self.settings.clash_group
                        )
                        self.clash_last_discovery = time.monotonic()
                    targets = self.settings.ai_probe_targets or []
                    values = self._probe_ai_targets(targets)
                    names = "/".join(target["name"] for target in targets)
                    self.link_source = f"AI HTTPS {names} via Clash {self.clash_group}"
                except Exception as exc:
                    self.clash_node = ""
                    self.link_source = "ICMP 回退"
                    log(f"clash monitor fallback: {exc}")
            if not values and not self.clash_node:
                for target in self.settings.ping_targets or [self.settings.ping_target]:
                    values.append(ping_once(target, self.settings.ping_timeout_ms))
            with self.lock:
                self.metrics.add_batch(values or [None])
            user32.PostMessageW(self.hwnd, WM_APP_UPDATE, 0, 0)
            interval = self.settings.ai_probe_interval if self.clash_node else self.settings.ping_interval
            self.stop.wait(max(0.1, interval - (time.monotonic() - started)))

    def _ip_loop(self) -> None:
        while not self.stop.is_set():
            self._refresh_risk()
            self.stop.wait(max(15, self.settings.ip_check_interval))

    def _refresh_risk(self, force: bool = False) -> None:
        if self.risk_busy:
            return
        self.risk_busy = True
        try:
            ip = get_public_ip()
            with self.lock:
                previous = self.last_ip
                stale = time.time() - self.risk.updated_at >= self.settings.risk_refresh_interval
            if force or ip != previous or stale:
                data = query_risk(
                    ip,
                    self.settings.proxycheck_api_key,
                    self.settings.ipqs_api_key,
                    self.settings.abuseipdb_api_key,
                )
                with self.lock:
                    self.last_ip, self.risk = ip, data
                log(
                    f"risk updated ip={ip} composite={data.score} "
                    f"pc={data.proxycheck_score} ia={data.ipapi_flags} "
                    f"iq={data.ipqs_score} ab={data.abuse_score} sources={data.source_count}"
                )
                user32.PostMessageW(self.hwnd, WM_APP_UPDATE, 0, 0)
        except Exception as exc:
            log(f"risk refresh failed: {exc}")
            with self.lock:
                self.risk.error = str(exc)
            user32.PostMessageW(self.hwnd, WM_APP_UPDATE, 0, 0)
        finally:
            self.risk_busy = False

    def run(self) -> int:
        log(f"starting native {APP_VERSION}")
        threading.Thread(target=self._ping_loop, daemon=True).start()
        threading.Thread(target=self._ip_loop, daemon=True).start()
        message = wt.MSG()
        while user32.GetMessageW(ctypes.byref(message), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(message))
            user32.DispatchMessageW(ctypes.byref(message))
        self.settings.save()
        for font in self._fonts:
            gdi32.DeleteObject(font)
        return int(message.wParam)


def main() -> int:
    if os.name != "nt":
        return 1
    try:
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except Exception:
            pass
        return NativeApp().run()
    except Exception as exc:
        log(f"fatal: {exc}")
        user32.MessageBoxW(None, f"VPNCheck 启动失败：\n{exc}\n\n日志：{LOG_PATH}", APP_NAME, 0x10)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

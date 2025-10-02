# -*- coding: utf-8 -*-
"""
Module: secure_pycurl_v3_shutdown.py
Mục đích:
1. Anti-Patching/Anti-Hook (ModuleProxy, CurlProxy).
2. Tự phục hồi (Monitor Thread, Integrity Checker).
3. Tách biệt Network I/O sang Worker Process.
4. Xác thực giao tiếp Worker (HMAC/Nonce Auth).
5. **Thêm chính sách Zero-Tolerance:** Tắt công cụ (os._exit) ngay lập tức khi phát hiện hook hoặc tấn công.
"""

import sys
import time
import threading
import types
import io
import re
import gc
import base64
import json
import traceback
import multiprocessing
import hashlib
import hmac
import secrets
import inspect
import os
from time import sleep
from urllib.parse import urlencode, urlparse, urlunparse, parse_qsl

# --- Tham số cấu hình ---
_MONITOR_INTERVAL = 0.8  # giám sát interval (giây)
_PROTECT_NAMES = {"Curl", "Curl.perform", "Curl.setopt", "Curl_factory"}
_MAX_GC_SCAN = 20000      # giới hạn scan gc.get_objects() để tránh tắc
_WORKER_NAME = "pycurl_secure_worker_v3"

# ==============================================================================
# I. Lớp Bảo Mật Nâng Cao & Chức năng Tự Đóng (Shutdown Functionality)
# ==============================================================================

# --- HÀM MỚI: TỰ ĐÓNG CÔNG CỤ AN TOÀN ---
def _terminate_tool_immediately(reason="Security Breach Detected"):
    """Dọn dẹp và tắt công cụ ngay lập tức khi phát hiện hook/tấn công."""
    print(f"\n[!!! SECURITY TERMINATION !!!] Tắt công cụ: {reason}", file=sys.stderr)
    try:
        # 1. Log traceback hiện tại (giúp debug nếu cần)
        traceback.print_stack()
        # 2. Dừng worker process một cách an toàn
        global _worker_mgr
        if _worker_mgr:
            _worker_mgr.stop() 
    except Exception:
        pass
    # 3. Bắt buộc thoát chương trình ngay lập tức (không chạy khối finally/cleanup)
    os._exit(1) 

class BytecodeIntegrityChecker:
    """Kiểm tra toàn vẹn bytecode của các hàm quan trọng."""
    def __init__(self):
        self._checksums = {}
        self._lock = threading.Lock()
    
    def register(self, func, name=None):
        with self._lock:
            name = name or f"{func.__module__}.{func.__qualname__}"
            try:
                code_bytes = func.__code__.co_code
                self._checksums[name] = hashlib.sha256(code_bytes).digest()
                return True
            except Exception:
                return False
    
    def verify(self, func, name=None):
        with self._lock:
            name = name or f"{func.__module__}.{func.__qualname__}"
            if name not in self._checksums:
                return True
            try:
                current = hashlib.sha256(func.__code__.co_code).digest()
                return current == self._checksums[name]
            except Exception:
                # Nếu không thể verify (ví dụ: func bị thay đổi thành object không có __code__), coi là thất bại.
                return False

class CallerValidator:
    """Xác thực stack frame gọi hàm để phát hiện các module hook."""
    def __init__(self):
        self._suspicious_patterns = [
            'hook', 'inject', 'monkey', 'patch', 'frida', 
            'mitmproxy', 'burp', 'intercept', 'debug', 'trace',
        ]
    
    def validate_caller(self, max_depth=15):
        try:
            frame = inspect.currentframe()
            depth = 0
            suspicious_frames = []
            
            # Bỏ qua 2 frame đầu tiên (chính validator và hàm gọi nó)
            if frame: frame = frame.f_back
            if frame: frame = frame.f_back

            while frame and depth < max_depth:
                frame_info = inspect.getframeinfo(frame)
                filename = frame_info.filename.lower()
                
                for pattern in self._suspicious_patterns:
                    if pattern in filename or pattern in frame.f_code.co_name.lower():
                        suspicious_frames.append({
                            'file': filename,
                            'function': frame.f_code.co_name,
                            'pattern': pattern
                        })
                
                frame = frame.f_back
                depth += 1
            
            if suspicious_frames:
                # Trả về False để kích hoạt _terminate_tool_immediately()
                return False, f"Patterns: {[f['pattern'] for f in suspicious_frames][:3]}..."
            return True, None
            
        except Exception as e:
            return False, f"Caller check internal error: {e}"
        finally:
            del frame

class AntiDebugger:
    """Kiểm tra các dấu hiệu của debugger."""
    def check_debugger(self):
        checks = []
        # Check sys.gettrace()
        if sys.gettrace() is not None:
             return False
        
        # Check for common debug environment variables
        if os.environ.get('PYCHARM_HOSTED') or os.environ.get('VSCODE_CWD') or os.environ.get('DEBUGPY_PROCESS_ID'):
            return False
        
        return True

class RequestAuthenticator:
    """Tạo và xác thực HMAC/Nonce để bảo vệ giao tiếp giữa Parent và Worker."""
    def __init__(self, secret=None):
        self._secret = secret or secrets.token_bytes(32)
    
    def get_secret(self):
        return self._secret
    
    def sign_request(self, url, method, body_hash=""):
        timestamp = int(time.time() * 1000)
        nonce = secrets.token_hex(16)
        message = f"{url}|{method}|{timestamp}|{body_hash}|{nonce}".encode()
        signature = hmac.new(self._secret, message, hashlib.sha256).hexdigest()
        
        return {
            'signature': signature,
            'nonce': nonce,
            'timestamp': timestamp
        }
    
    def verify_request(self, url, method, body_hash, signature, nonce, timestamp):
        # Check Time window (300000ms tolerance = 5 phút)
        if abs(int(time.time() * 1000) - timestamp) > 300000:
             return False, "Timestamp skew or expired"

        message = f"{url}|{method}|{timestamp}|{body_hash}|{nonce}".encode()
        expected = hmac.new(self._secret, message, hashlib.sha256).hexdigest()
        
        if not hmac.compare_digest(signature, expected):
            return False, "Signature mismatch"
        
        return True, "OK"

# Global instances cho Parent Process
_integrity_checker = BytecodeIntegrityChecker()
_caller_validator = CallerValidator()
_anti_debugger = AntiDebugger()
_authenticator = RequestAuthenticator()

# ==============================================================================
# II. Proxy & Monitor (Anti-Hook Core)
# ==============================================================================

# --- ModuleProxy nâng cao ---
class ModuleProxy(types.ModuleType):
    """Module proxy chặn setattr ra bên ngoài với danh sách tên bị bảo vệ."""
    def __init__(self, real_mod, blocked_names):
        super().__init__(real_mod.__name__)
        object.__setattr__(self, "_real_mod", real_mod)
        object.__setattr__(self, "_blocked", set(blocked_names))
    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_real_mod"), name)
    def __repr__(self):
        return repr(object.__getattribute__(self, "_real_mod"))
    def __dir__(self):
        return dir(object.__getattribute__(self, "_real_mod"))
    def __setattr__(self, name, value):
        blocked = object.__getattribute__(self, "_blocked")
        if name in blocked or any(name == n.split(".", 1)[0] for n in blocked):
            raise AttributeError(f"Setting attribute {name} on module {self.__name__} is blocked")
        setattr(object.__getattribute__(self, "_real_mod"), name, value)

# --- CurlProxy để bọc instance ---
class CurlProxy:
    __slots__ = ("_impl", "_orig_perform", "_orig_setopt")
    def __init__(self, impl, orig_perform, orig_setopt):
        object.__setattr__(self, "_impl", impl)
        object.__setattr__(self, "_orig_perform", orig_perform)
        object.__setattr__(self, "_orig_setopt", orig_setopt)
    def perform(self):
        # Gây lỗi bảo mật nếu bị hook. Lỗi này sẽ bị bắt bởi Monitor/GC nếu nó là một instance cũ.
        # Ở v3, logic kiểm tra đã được chuyển ra ngoài send_request_via_worker.
        # Nếu ai đó gọi pycurl.Curl().perform() trực tiếp, nó vẫn bị kiểm tra:
        ok, reason = _caller_validator.validate_caller()
        if not ok:
            raise PermissionError(f"Suspicious caller detected: {reason}")
        if not _anti_debugger.check_debugger():
            raise RuntimeError("Debugger/Suspicious environment detected")
        return self._orig_perform(self._impl)
    def setopt(self, option, value):
        ok, reason = _caller_validator.validate_caller()
        if not ok:
            raise PermissionError(f"Suspicious caller detected before setopt: {reason}")
        return self._orig_setopt(self._impl, option, value)
    def __getattr__(self, name):
        return getattr(self._impl, name)
    def __setattr__(self, name, value):
        if name in ("perform", "setopt"):
            raise AttributeError("Modification of perform/setopt is not allowed")
        if name in self.__slots__:
            object.__setattr__(self, name, value)
            return
        setattr(self._impl, name, value)

# --- Hàm bảo vệ pycurl mạnh hơn ---
def protect_pycurl_enhanced(monitor_interval=_MONITOR_INTERVAL, blocked_names=None, aggressive_fix=True):
    """Cài đặt ModuleProxy, CurlProxy và Monitor tự phục hồi."""
    blocked_names = blocked_names or _PROTECT_NAMES
    try:
        import pycurl as _pycurl
    except Exception as e:
        return {"ok": False, "reason": f"Không import pycurl: {e}"}

    RealCurl = getattr(_pycurl, "Curl", None)
    if RealCurl is None:
        return {"ok": False, "reason": "pycurl không có Curl"}

    orig_perform = getattr(RealCurl, "perform", None)
    orig_setopt = getattr(RealCurl, "setopt", None)

    if orig_perform is None or orig_setopt is None:
        return {"ok": False, "reason": "Không tìm perform/setopt trên Curl"}

    # Register bytecode checksums
    _integrity_checker.register(orig_perform, name="pycurl.Curl.perform_orig")
    _integrity_checker.register(orig_setopt, name="pycurl.Curl.setopt_orig")

    # factory tạo CurlProxy
    def Curl_factory(*args, **kwargs):
        impl = RealCurl(*args, **kwargs)
        return CurlProxy(impl, orig_perform, orig_setopt)

    # replace Curl trên module gốc
    try:
        setattr(_pycurl, "Curl", Curl_factory)
        _integrity_checker.register(Curl_factory, name="pycurl.Curl_factory")
    except Exception as e:
        return {"ok": False, "reason": f"Không thể set Curl trên module pycurl: {e}"}

    # bọc module bằng ModuleProxy để chặn setattr
    try:
        mod_proxy = ModuleProxy(_pycurl, blocked_names)
        sys.modules["pycurl"] = mod_proxy
    except Exception as e:
        try:
            setattr(_pycurl, "Curl", RealCurl)
        except Exception:
            pass
        return {"ok": False, "reason": f"Không thể bọc module pycurl bằng ModuleProxy: {e}"}

    # --- helper: replace old references trong sys.modules ---
    def replace_old_references(real_cls=RealCurl, factory=Curl_factory):
        """Thay thế các tham chiếu Curl cũ trong sys.modules."""
        for mname, mod in list(sys.modules.items()):
            try:
                if not hasattr(mod, "__dict__"):
                    continue
                for attr, val in list(mod.__dict__.items()):
                    try:
                        if val is real_cls:
                            try:
                                setattr(mod, attr, factory)
                            except Exception:
                                pass
                    except Exception:
                        continue
            except Exception:
                continue

    # --- helper: patch existing instances ---
    def patch_existing_instances(real_cls=RealCurl, orig_perf=orig_perform, orig_setopt=orig_setopt, limit=_MAX_GC_SCAN):
        """Dò qua gc.get_objects() và đặt lại perform/setopt cho instance bị hook."""
        try:
            objs = gc.get_objects()
        except Exception:
            return
        scanned = 0
        for obj in objs:
            scanned += 1
            if scanned > limit:
                break
            try:
                cls = getattr(obj, "__class__", None)
                if cls is RealCurl or (getattr(cls, "__module__", "") == getattr(RealCurl, "__module__", "") and getattr(cls, "__name__", "") == getattr(RealCurl, "__name__", "")):
                    try:
                        if getattr(obj.perform, '__self__', None) is not obj or getattr(obj.perform, '__func__', None) is not orig_perf:
                            setattr(obj, "perform", types.MethodType(orig_perf, obj))
                        if getattr(obj.setopt, '__self__', None) is not obj or getattr(obj.setopt, '__func__', None) is not orig_setopt:
                            setattr(obj, "setopt", types.MethodType(orig_setopt, obj))
                    except Exception:
                        pass
            except Exception:
                continue

    # --- Monitor thread (self-healing) ---
    def _monitor_loop():
        while True:
            try:
                # 1. Kiểm tra toàn vẹn bytecode
                if not _integrity_checker.verify(Curl_factory, name="pycurl.Curl_factory"):
                    print("[SECURITY ALERT] Bytecode of Curl_factory has been modified! Re-patching...", file=sys.stderr)
                    # Nếu bytecode bị thay đổi, kích hoạt tự đóng vì đây là tấn công nghiêm trọng
                    _terminate_tool_immediately("Critical Bytecode Integrity Failure.")

                # 2. Kiểm tra và phục hồi Curl trên module
                mod = sys.modules.get("pycurl")
                real_mod = getattr(mod, "_real_mod", mod)
                cobj = getattr(real_mod, "Curl", None)
                if cobj is None or (cobj is not Curl_factory and not isinstance(cobj, CurlProxy)):
                    try:
                        print(f"[SECURITY ALERT] pycurl.Curl was replaced ({type(cobj)}). Restoring...", file=sys.stderr)
                        setattr(real_mod, "Curl", Curl_factory)
                        replace_old_references()
                    except Exception:
                        pass
                
                # 3. Patch instances định kỳ nếu aggressive
                if aggressive_fix:
                    try:
                        patch_existing_instances()
                    except Exception:
                        pass

            except Exception as e:
                # không để monitor die
                print(f"[ERROR] Monitor loop failed: {e}", file=sys.stderr)
                pass
            time.sleep(monitor_interval)

    t = threading.Thread(target=_monitor_loop, daemon=True, name="pycurl-protect-monitor")
    t.start()

    return {"ok": True, "reason": "protect installed, monitor running"}

# ==============================================================================
# III. Worker Process (Isolation & Authentication)
# ==============================================================================

def _pycurl_worker_entry(conn, auth_secret):
    """Entrypoint cho worker process với authentication."""
    worker_auth = RequestAuthenticator(secret=auth_secret)
    
    try:
        import pycurl
        import certifi
    except Exception as e:
        try:
            conn.send(json.dumps({"err": f"Worker import failed: {e}"}))
        except Exception:
            pass
        conn.close()
        return

    while True:
        try:
            if not conn.poll(timeout=0.1):
                continue
            
            msg = conn.recv()
            if not msg or msg == "":
                continue
            
            try:
                if isinstance(msg, bytes):
                    msg = msg.decode('utf-8')
                obj = json.loads(msg)
            except Exception as e:
                conn.send(json.dumps({"err": f"Invalid JSON command: {e}"}))
                continue
            
            cmd = obj.get("cmd")
            if cmd == "exit":
                conn.send(json.dumps({"ok": True}))
                break
            
            if cmd == "handshake":
                conn.send(json.dumps({"ok": True, "worker_id": os.getpid()}))
                continue
            
            if cmd != "request":
                conn.send(json.dumps({"err": "Unknown command"}))
                continue
            
            # Xử lý Request
            p = obj.get("payload", {})
            auth = obj.get("auth", {})
            
            url = p.get("url", "")
            method = (p.get("method") or "GET").upper()
            
            # 1. Xử lý Body và Hash
            body_bytes = None
            data = p.get("data")
            json_body = p.get("json") # Dùng tên 'json' để tương thích với user
            if json_body is not None:
                body_bytes = json.dumps(json_body).encode("utf-8")
            elif data:
                if isinstance(data, dict):
                    body_bytes = urlencode(data, doseq=True).encode("utf-8")
                elif isinstance(data, str):
                    body_bytes = data.encode("utf-8")
                elif isinstance(data, (bytes, bytearray)):
                    body_bytes = bytes(data)
            
            body_hash = hashlib.sha256(body_bytes or b"").hexdigest()
            
            # 2. Xác thực Request (Authentication)
            is_valid, reason = worker_auth.verify_request(
                url, method, body_hash, 
                auth.get('signature', ''), auth.get('nonce', ''), auth.get('timestamp', 0)
            )
            if not is_valid:
                # Trả về lỗi Authentication để Parent Process tự đóng
                conn.send(json.dumps({"err": f"Authentication failed: {reason}"}))
                continue
            
            # 3. Thực hiện Request (Pycurl Logic)
            # ... (Giữ nguyên logic pycurl request)
            headers = p.get("headers") or {}
            cookies = p.get("cookies")
            params = p.get("params")
            proxy = p.get("proxy")
            timeout = p.get("timeout", 15)
            connect_timeout = p.get("connect_timeout", 10)
            follow_redirects = p.get("follow_redirects", True)
            verify = p.get("verify", True)

            if params:
                parsed = urlparse(url)
                q = dict(parse_qsl(parsed.query))
                q.update(params)
                url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, urlencode(q, doseq=True), parsed.fragment))

            header_list = []
            if headers:
                for k, v in headers.items():
                    header_list.append(f"{k}: {v}")
            if cookies:
                if isinstance(cookies, dict):
                    cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
                else:
                    cookie_header = str(cookies)
                header_list.append(f"Cookie: {cookie_header}")

            if body_bytes is not None and not any(h.lower().startswith("content-type:") for h in header_list):
                 if json_body is not None:
                    header_list.append("Content-Type: application/json; charset=utf-8")
                 elif isinstance(data, dict):
                    header_list.append("Content-Type: application/x-www-form-urlencoded")

            buf = io.BytesIO()
            header_buf = io.BytesIO()
            c = pycurl.Curl()
            
            try:
                c.setopt(pycurl.URL, url)
                c.setopt(pycurl.WRITEFUNCTION, buf.write)
                c.setopt(pycurl.HEADERFUNCTION, header_buf.write)
                c.setopt(pycurl.CONNECTTIMEOUT, int(connect_timeout))
                c.setopt(pycurl.TIMEOUT, int(timeout))
                c.setopt(pycurl.FOLLOWLOCATION, bool(follow_redirects))
                c.setopt(pycurl.NOSIGNAL, 1)
                
                if verify:
                    try:
                        c.setopt(pycurl.CAINFO, certifi.where())
                    except Exception:
                        c.setopt(pycurl.SSL_VERIFYPEER, 0)
                        c.setopt(pycurl.SSL_VERIFYHOST, 0)
                else:
                    c.setopt(pycurl.SSL_VERIFYPEER, 0)
                    c.setopt(pycurl.SSL_VERIFYHOST, 0)
                
                if proxy:
                    c.setopt(pycurl.PROXY, proxy)
                
                if method == "GET":
                    c.setopt(pycurl.HTTPGET, 1)
                elif method == "POST":
                    c.setopt(pycurl.POST, 1)
                    if body_bytes is not None:
                        c.setopt(pycurl.POSTFIELDS, body_bytes)
                        c.setopt(pycurl.POSTFIELDSIZE, len(body_bytes))
                else:
                    c.setopt(pycurl.CUSTOMREQUEST, method)
                    if body_bytes is not None:
                        c.setopt(pycurl.POSTFIELDS, body_bytes)
                        c.setopt(pycurl.POSTFIELDSIZE, len(body_bytes))
                
                if header_list:
                    c.setopt(pycurl.HTTPHEADER, header_list)
                if not any(h.lower().startswith("user-agent:") for h in header_list):
                    c.setopt(pycurl.USERAGENT, "Mozilla/5.0 (SecureWorker/v3)")
                
                c.perform()
                
                status = c.getinfo(pycurl.RESPONSE_CODE)
                raw_body = buf.getvalue()
                raw_headers = header_buf.getvalue().decode("latin-1", errors="replace")
                body_b64 = base64.b64encode(raw_body).decode("ascii")
                
                response = {
                    "status": status,
                    "headers": raw_headers,
                    "body_b64": body_b64,
                    "err": None
                }
                
                conn.send(json.dumps(response))
                
            except Exception as e:
                tb = traceback.format_exc()
                conn.send(json.dumps({"err": str(e), "trace": tb}))
            finally:
                try:
                    c.close()
                    buf.close()
                    header_buf.close()
                except Exception:
                    pass
                    
        except EOFError:
            break
        except Exception:
            break
    
    try:
        conn.close()
    except Exception:
        pass

# --- Manager cho worker process ---
class PycurlWorkerManager:
    def __init__(self):
        self.proc = None
        self.parent_conn = None
        self.child_conn = None
        self._lock = threading.Lock()
        self.auth_secret = _authenticator.get_secret()

    def start(self):
        with self._lock:
            if self.proc and self.proc.is_alive():
                return True
            
            try:
                self.parent_conn, self.child_conn = multiprocessing.Pipe()
                self.proc = multiprocessing.Process(
                    target=_pycurl_worker_entry,
                    args=(self.child_conn, self.auth_secret),
                    name=_WORKER_NAME,
                    daemon=True
                )
                self.proc.start()
                time.sleep(0.3)
                
                if not self.proc.is_alive():
                    raise RuntimeError("Worker died immediately")
                
                self.parent_conn.send(json.dumps({"cmd": "handshake"}))
                if self.parent_conn.poll(timeout=2.0):
                    resp = self.parent_conn.recv()
                    data = json.loads(resp)
                    if not data.get("ok"):
                        raise RuntimeError(f"Handshake failed: {data.get('err', 'Unknown')}")
                else:
                    raise RuntimeError("Handshake timeout")
                
                return True
            except Exception as e:
                self.stop()
                raise RuntimeError(f"Worker start failed: {e}")
    
    def stop(self):
        with self._lock:
            try:
                if self.parent_conn:
                    self.parent_conn.send(json.dumps({"cmd": "exit"}))
                if self.proc:
                    self.proc.join(timeout=1.0)
                    if self.proc.is_alive():
                        self.proc.terminate()
            except Exception:
                pass
            finally:
                try:
                    if self.parent_conn:
                        self.parent_conn.close()
                    if self.child_conn:
                        self.child_conn.close()
                except Exception:
                    pass
                self.proc = None
                self.parent_conn = None
                self.child_conn = None

    def request(self, payload, timeout=30):
        with self._lock:
            if not self.proc or not self.proc.is_alive():
                self.start()
            
            try:
                # 1. Tính Body Hash
                data = payload.get("data")
                json_body = payload.get("json") # Dùng tên 'json'
                
                body_bytes = None
                if json_body is not None:
                    body_bytes = json.dumps(json_body).encode("utf-8")
                elif isinstance(data, dict):
                    body_bytes = urlencode(data, doseq=True).encode("utf-8")
                elif isinstance(data, str):
                    body_bytes = data.encode("utf-8")
                elif isinstance(data, (bytes, bytearray)):
                    body_bytes = bytes(data)
                
                body_hash = hashlib.sha256(body_bytes or b"").hexdigest()

                # 2. Ký request
                auth_data = _authenticator.sign_request(
                    payload.get("url", ""), payload.get("method", "GET"), body_hash
                )

                # 3. Gửi command
                msg_to_send = json.dumps({
                    "cmd": "request",
                    "payload": payload,
                    "auth": auth_data
                })
                self.parent_conn.send(msg_to_send)
                
                # 4. Chờ phản hồi (có timeout)
                wait_time = 0
                poll_interval = 0.1
                while wait_time < timeout:
                    if self.parent_conn.poll(timeout=poll_interval):
                        resp = self.parent_conn.recv()
                        return json.loads(resp)
                    wait_time += poll_interval
                
                raise TimeoutError("Request timeout")
            except Exception as e:
                return {"err": f"Request failed: {e}"}

# ==============================================================================
# IV. API Công Cộng
# ==============================================================================

_worker_mgr = None
_worker_lock = threading.Lock()

def protect_and_start_worker(use_worker=True, aggressive_fix=True):
    """
    Cài đặt bảo vệ pycurl và (tùy chọn) start worker.
    """
    res = protect_pycurl_enhanced(aggressive_fix=aggressive_fix)
    global _worker_mgr
    if use_worker and _worker_mgr is None:
        _worker_mgr = PycurlWorkerManager()
        try:
            _worker_mgr.start()
        except RuntimeError as e:
            # Nếu worker start fail, coi là lỗi nghiêm trọng và tự đóng
            _terminate_tool_immediately(f"Worker start failed: {e}")
    return res

def stop_worker():
    global _worker_mgr
    if _worker_mgr:
        _worker_mgr.stop()
        _worker_mgr = None

def send_request_via_worker(
    url,
    method="GET",
    headers=None,
    cookies=None,
    params=None,
    data=None,
    json=None, # Đổi thành 'json' để tương thích với cách gọi của bạn
    proxy=None,
    timeout=15,
    connect_timeout=10,
    follow_redirects=True,
    verify=True
):
    """
    Gửi request an toàn thông qua worker process.
    Nếu phát hiện hook/tấn công, sẽ gọi _terminate_tool_immediately().
    """
    global _worker_mgr
    with _worker_lock:
        if _worker_mgr is None:
            # Nếu chưa start, tự start. Logic start bên trong đã có kiểm tra lỗi.
            _worker_mgr = PycurlWorkerManager()
            try:
                _worker_mgr.start()
            except RuntimeError as e:
                 _terminate_tool_immediately(f"Worker start failed: {e}")
    
    # 1. KIỂM TRA BẢO MẬT TRƯỚC KHI GỬI LỆNH (Parent Process)
    
    # Kiểm tra Anti Debugger/Suspicious Environment
    if not _anti_debugger.check_debugger():
        _terminate_tool_immediately("Debugger/Suspicious Environment detected.")

    # Kiểm tra Caller Validator (Stack trace)
    ok, reason = _caller_validator.validate_caller()
    if not ok:
        _terminate_tool_immediately(f"Suspicious Caller detected. Reason: {reason}")
    
    payload = {
        "url": url,
        "method": method,
        "headers": headers,
        "cookies": cookies,
        "params": params,
        "data": data,
        "json": json,
        "proxy": proxy,
        "timeout": timeout,
        "connect_timeout": connect_timeout,
        "follow_redirects": follow_redirects,
        "verify": verify
    }
    
    # 2. THỰC HIỆN REQUEST VÀ KIỂM TRA LỖI BẢO MẬT SAU KHI THỰC HIỆN
    result = _worker_mgr.request(payload, timeout=timeout + 5)
    
    # Kiểm tra xem Worker có báo lỗi Authentication (hook pipe) hay không
    err_msg = result.get("err", "")
    if err_msg and ("Authentication failed" in err_msg or "Signature mismatch" in err_msg):
        _terminate_tool_immediately(f"Inter-Process Auth failed: {err_msg}")
    
    return result

# --- Khi run trực tiếp, demo nhanh ---
if __name__ == "__main__":
    print("=" * 60)
    print("Secure PyCurl v3 - Demo (Kèm Tự Đóng)")
    print("=" * 60)
    
    print("\n[1] Khởi bảo vệ pycurl + worker...")
    try:
        r = protect_and_start_worker(use_worker=True, aggressive_fix=True)
        print("    Protect result:", r)
    except Exception as e:
        print(f"    ✗ Khởi động thất bại: {e}")
        sys.exit(1)
        
    print("\n[2] Testing GET request qua worker...")
    out = send_request_via_worker("https://httpbin.org/get", params={"q":"v3_test"})
    if out.get("err"):
        print(f"    ✗ Worker error: {out.get('err')}")
    else:
        body = base64.b64decode(out.get("body_b64", ""))
        print(f"    ✓ Status: {out.get('status')}")
        print(f"    Body preview (utf-8): {body.decode('utf-8', errors='replace')[:200]}...")
    
    print("\n[3] Testing POST request qua worker...")
    out = send_request_via_worker(
        "https://httpbin.org/post", 
        method="POST", 
        json={"name": "v3", "value": "secure"} # Đã sửa thành 'json'
    )
    if out.get("err"):
        print(f"    ✗ Worker error: {out.get('err')}")
    else:
        body = base64.b64decode(out.get("body_b64", ""))
        print(f"    ✓ Status: {out.get('status')}")
        print(f"    Body preview (utf-8): {body.decode('utf-8', errors='replace')[:200]}...")
    
    print("\n[4] Dừng worker...")
    stop_worker()
    print("    ✓ Worker đã dừng")
    
    print("\n" + "=" * 60)
    print("Test hoàn tất!")
    print("=" * 60)

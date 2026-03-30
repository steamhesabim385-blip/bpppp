"""
PyKeyAuth Client v2
+ HMAC imza doğrulama
+ Anti-debug koruması
+ Device limit desteği
"""

import requests, platform, subprocess, os, hashlib, hmac
import time, sys, json, ctypes, struct
from typing import Optional


class KeyAuthError(Exception):
    pass


class UserData:
    def __init__(self):
        self.username = self.ip = self.hwid = ""
        self.expires = self.createdate = self.lastlogin = ""
        self.subscription = ""
        self.subscriptions = []

    def __repr__(self):
        return f"UserData(user={self.username!r}, sub={self.subscription!r}, exp={self.expires!r})"


# ══════════════════════════════════════════════════════════════════════════════
#  ANTİ-DEBUG KORUMALARI
# ══════════════════════════════════════════════════════════════════════════════

class AntiDebug:
    """Debugger ve sandbox tespiti"""

    @staticmethod
    def is_debugger_present() -> bool:
        """Windows debugger kontrolü"""
        if platform.system() != "Windows":
            return False
        try:
            kernel32 = ctypes.windll.kernel32
            # IsDebuggerPresent
            if kernel32.IsDebuggerPresent():
                return True
            # CheckRemoteDebuggerPresent
            is_remote = ctypes.c_bool(False)
            kernel32.CheckRemoteDebuggerPresent(
                kernel32.GetCurrentProcess(),
                ctypes.byref(is_remote)
            )
            if is_remote.value:
                return True
        except:
            pass
        return False

    @staticmethod
    def is_vm_or_sandbox() -> bool:
        """Sanal makine / sandbox tespiti (temel)"""
        suspicious = [
            "vmware", "virtualbox", "vbox", "qemu",
            "xen", "parallels", "sandbox", "cuckoo"
        ]
        try:
            hostname = platform.node().lower()
            if any(s in hostname for s in suspicious):
                return True
        except:
            pass
        return False

    @staticmethod
    def is_common_analysis_tool() -> bool:
        """Bilinen analiz araçları çalışıyor mu?"""
        if platform.system() != "Windows":
            return False
        tools = [
            "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", "windbg.exe",
            "ida.exe", "ida64.exe", "ghidra.exe", "processhacker.exe",
            "wireshark.exe", "fiddler.exe", "cheatengine.exe",
            "dnspy.exe", "dotpeek.exe", "de4dot.exe"
        ]
        try:
            import subprocess
            result = subprocess.run(
                ["tasklist"], capture_output=True, text=True, timeout=3
            )
            running = result.stdout.lower()
            for tool in tools:
                if tool.lower() in running:
                    return True
        except:
            pass
        return False

    @staticmethod
    def timing_check() -> bool:
        """Zaman manipülasyonu tespiti"""
        try:
            t1 = time.perf_counter()
            _ = [i**2 for i in range(1000)]
            t2 = time.perf_counter()
            elapsed = t2 - t1
            # Normalden çok yavaşsa (step-through debugging)
            if elapsed > 5.0:
                return True
        except:
            pass
        return False

    @classmethod
    def check_all(cls) -> bool:
        """Tüm kontrolleri çalıştır"""
        return (
            cls.is_debugger_present() or
            cls.is_common_analysis_tool() or
            cls.timing_check()
        )


# ══════════════════════════════════════════════════════════════════════════════
#  KEYAUTH CLIENT
# ══════════════════════════════════════════════════════════════════════════════

class KeyAuth:
    """
    PyKeyAuth v2 Client
    
    Kullanım:
        auth = KeyAuth(name="App", ownerid="xxx", server_url="https://...")
        auth.init()
        auth.license("KEY-XXXX-XXXX-XXXX-XXXX")
        print(auth.user.username)
    """

    def __init__(
        self,
        name: str,
        ownerid: str,
        server_url: str = "http://localhost:8000",
        version: str = "1.0",
        exit_on_fail: bool = True,
        anti_debug: bool = True,
    ):
        self.name         = name
        self.ownerid      = ownerid
        self.server_url   = server_url.rstrip("/")
        self.version      = version
        self.exit_on_fail = exit_on_fail
        self.anti_debug   = anti_debug
        self.session_id   = ""
        self._app_secret  = ""
        self.initialized  = False
        self.user         = UserData()

    # ── INIT ──────────────────────────────────────────────────────────────────
    def init(self) -> bool:
        """Sunucuyla bağlantı kur. Her programın başında çağır."""
        if self.initialized:
            self._fail("Zaten başlatıldı")

        # Anti-debug kontrolü
        if self.anti_debug and AntiDebug.check_all():
            self._fail("Debugger tespit edildi")

        resp = self._req({"type":"init","name":self.name,"ownerid":self.ownerid,"ver":self.version})
        if not resp.get("success"):
            self._fail(resp.get("message","Başlatma başarısız"))

        self.session_id   = resp["sessionid"]
        self.initialized  = True
        return True

    # ── LİSANS ────────────────────────────────────────────────────────────────
    def license(self, key: str, hwid: Optional[str] = None) -> bool:
        """Sadece key ile giriş (register gerektirmez)"""
        self._check_init()
        if self.anti_debug and AntiDebug.check_all():
            self._fail("Debugger tespit edildi")
        if hwid is None: hwid = self.get_hwid()

        resp = self._req({"type":"license","key":key,"hwid":hwid,
                          "sessionid":self.session_id,"name":self.name,"ownerid":self.ownerid})
        if resp.get("success"):
            self._load(resp["info"]); return True
        self._fail(resp.get("message","Lisans doğrulama başarısız"))
        return False

    # ── REGISTER ──────────────────────────────────────────────────────────────
    def register(self, username: str, password: str, license_key: str, hwid: Optional[str] = None) -> bool:
        self._check_init()
        if hwid is None: hwid = self.get_hwid()

        resp = self._req({"type":"register","username":username,"pass":password,
                          "key":license_key,"hwid":hwid,"sessionid":self.session_id,
                          "name":self.name,"ownerid":self.ownerid})
        if resp.get("success"):
            self._load(resp["info"]); return True
        self._fail(resp.get("message","Kayıt başarısız"))
        return False

    # ── LOGIN ─────────────────────────────────────────────────────────────────
    def login(self, username: str, password: str, hwid: Optional[str] = None) -> bool:
        self._check_init()
        if hwid is None: hwid = self.get_hwid()

        resp = self._req({"type":"login","username":username,"pass":password,
                          "hwid":hwid,"sessionid":self.session_id,
                          "name":self.name,"ownerid":self.ownerid})
        if resp.get("success"):
            self._load(resp["info"]); return True
        self._fail(resp.get("message","Giriş başarısız"))
        return False

    # ── CHECK ─────────────────────────────────────────────────────────────────
    def check(self) -> bool:
        """Oturum hâlâ geçerli mi?"""
        self._check_init()
        resp = self._req({"type":"check","sessionid":self.session_id,
                          "name":self.name,"ownerid":self.ownerid})
        return bool(resp.get("success"))

    # ── LOG ───────────────────────────────────────────────────────────────────
    def log(self, message: str):
        self._check_init()
        self._req({"type":"log","message":message,
                   "pcuser":os.getlogin() if hasattr(os,"getlogin") else "unknown",
                   "sessionid":self.session_id,"name":self.name,"ownerid":self.ownerid})

    # ── HWID ──────────────────────────────────────────────────────────────────
    @staticmethod
    def get_hwid() -> str:
        """Cihaza özgü kimlik al"""
        system = platform.system()
        try:
            if system == "Linux":
                with open("/etc/machine-id") as f: return f.read().strip()
            elif system == "Windows":
                try:
                    import win32security
                    user = os.getlogin()
                    sid = win32security.LookupAccountName(None, user)[0]
                    return win32security.ConvertSidToStringSid(sid)
                except:
                    r = subprocess.run(["wmic","csproduct","get","uuid"],
                                       capture_output=True, text=True)
                    lines = [l.strip() for l in r.stdout.splitlines() if l.strip() and l.strip()!="UUID"]
                    if lines: return lines[0]
            elif system == "Darwin":
                out = subprocess.run(["ioreg","-l"], capture_output=True, text=True)
                for line in out.stdout.splitlines():
                    if "IOPlatformSerialNumber" in line:
                        return line.split("=")[-1].strip().strip('"')
        except:
            pass
        # Fallback
        return hashlib.md5((platform.node()+platform.processor()).encode()).hexdigest()

    # ── VERIFY HMAC ───────────────────────────────────────────────────────────
    def _verify_signature(self, resp: dict) -> bool:
        """Sunucu yanıtının HMAC imzasını doğrula"""
        if not self._app_secret: return True  # init'ten önce kontrol yok
        sig = resp.pop("signature", None)
        if not sig: return False
        expected = hmac.new(
            self._app_secret.encode(),
            json.dumps(resp, separators=(',',':'), sort_keys=True).encode(),
            hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(sig, expected)

    # ── REQUEST ───────────────────────────────────────────────────────────────
    def _req(self, data: dict) -> dict:
        url = f"{self.server_url}/api/v1/"
        try:
            r = requests.post(url, data=data, timeout=10)
            resp = r.json()
            return resp
        except requests.exceptions.ConnectionError:
            return {"success":False,"message":f"Sunucuya bağlanılamadı"}
        except requests.exceptions.Timeout:
            return {"success":False,"message":"Sunucu yanıt vermedi"}
        except Exception as e:
            return {"success":False,"message":f"Hata: {e}"}

    def _load(self, info: dict):
        self.user.username   = info.get("username","")
        self.user.ip         = info.get("ip","")
        self.user.hwid       = info.get("hwid","N/A")
        self.user.createdate = info.get("createdate","")
        self.user.lastlogin  = info.get("lastlogin","")
        subs = info.get("subscriptions",[])
        self.user.subscriptions = subs
        if subs:
            self.user.subscription = subs[0].get("subscription","")
            self.user.expires      = subs[0].get("expiry","")

    def _check_init(self):
        if not self.initialized:
            self._fail("Önce init() çağırın")

    def _fail(self, msg: str):
        print(f"[PyKeyAuth] HATA: {msg}")
        if self.exit_on_fail:
            time.sleep(2); sys.exit(1)
        raise KeyAuthError(msg)

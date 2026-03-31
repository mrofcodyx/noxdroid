# APK Check - Analisador de APK Android
# Detecta: protecao/ofuscacao, root, emulador, anti-debug, proxy, SDKs, hardcode, certificados.
# Traduzido do projeto Go ApkCheckPack.
# Uso standalone: python apk_check.py -f app.apk [--hardcode]
import argparse
import io
import os
import re
import sys
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

_R  = "\033[0m"
_G  = "\033[92m"
_Y  = "\033[93m"
_C  = "\033[96m"
_D  = "\033[90m"
_BD = "\033[1m"
_RE = "\033[91m"
_W  = "\033[97m"

def _sec(title):
    return "\n" + _C + _BD + "  [" + title + "]" + _R

def _ok(text):
    return "    " + _G + "[OK] " + _R + text

def _item(label, value=""):
    v = (" -> " + _W + value + _R) if value else ""
    return "      - " + label + v

# --- Mapa de protecoes/ofuscadores ---
PACK_MAP = {
    "360 Jiagu": {
        "sopath":  ["assets/libjiagu.so"],
        "soname":  ["libjiagu.so","libjgdtc.so","libjgdtc_a64.so","libjgdtc_art.so",
                    "libjgdtc_x64.so","libjgdtc_x86.so","libjiagu_a64.so",
                    "libjiagu_art.so","libjiagu_ls.so","libjiagu_x64.so","libjiagu_x86.so",
                    "libprotectClass.so","libSafeManageService.so"],
        "other":   ["assets/.appkey"],
        "soregex": [r"libjiagu_.+\.so", r"libjgdtc_.+\.so"],
        "jclass":  [],
    },
    "APKProtect": {
        "sopath":[], "soname":["libAPKProtect.so"], "other":[], "soregex":[], "jclass":[],
    },
    "apktoolplus": {
        "sopath":  ["lib/armeabi/libapktoolplus_jiagu.so"],
        "soname":  ["libapktoolplus_jiagu.so"],
        "other":   ["assets/jiagu_data.bin","assets/sign.bin"],
        "soregex": [], "jclass": [],
    },
    "CFCA Reforco": {
        "sopath":[], "soname":["libbasec.so","libbasec_x86.so","libseenh.so",
                               "libseenh_a64.so","libseenh_x86.so"],
        "other":["my_classes.jar"], "soregex":[], "jclass":[],
    },
    "DexProtect": {
        "sopath":[], "soname":[],
        "other":["assets/classes.dex.dat","dp.arm-v7.so.dat","dp.arm.so.dat"],
        "soregex":[], "jclass":[],
    },
    "OPPO Protect": {
        "sopath":[], "soname":["OPPOProtect.so","OPPOProtect2019.so"],
        "other":[], "soregex":[r"OPPOProtect\d{4}\.so"], "jclass":[],
    },
    "Naga (娜迦)": {
        "sopath":[], "soname":["libchaosvm p.so","libddog.so","libfdog.so","libhdog.so"],
        "other":[], "soregex":[r"lib.dog\.so"], "jclass":[],
    },
    "Naga Enterprise": {
        "sopath":[], "soname":["libedog.so"], "other":[], "soregex":[], "jclass":[],
    },
    "Naga VMP": {
        "sopath":[], "soname":["libvdog-x86.so","libvdog.so"],
        "other":[], "soregex":[r"libvdog-.+\.so"], "jclass":[],
    },
    "Naga 2022": {
        "sopath":["lib/armeabi/libxloader.so","lib/armeabi-v7a/libxloader.so","lib/arm64-v8a/libxloader.so"],
        "soname":["libxloader.so"], "other":["assets/maindata/fake_classes.dex"],
        "soregex":[], "jclass":[],
    },
    "Bangbang Enterprise": {
        "sopath":[], "soname":["libDexHelper-x86.so","libDexHelper.so"],
        "other":[], "soregex":[r"libDexHelper-.+\.so"], "jclass":[],
    },
    "Bangbang Free": {
        "sopath":["lib/armeabi/libSecShell-x86.so","lib/armeabi/libSecShell.so"],
        "soname":["libSecShell_art.so","libSecShell.so","libSecShel1.so","libsecexe.so","libsecmain.so"],
        "other":["assets/secData0.jar"], "soregex":[], "jclass":[],
    },
    "Bangbang Legacy": {
        "sopath":["lib/armeabi/DexHelper.so"],
        "soname":["DexHelper.so"], "other":["assets/classes.jar"],
        "soregex":[], "jclass":[],
    },
    "iJiami (爱加密)": {
        "sopath":["lib/armeabi/libitsec.so"],
        "soname":["libitsec.so"], "other":["assets/itse"],
        "soregex":[], "jclass":[],
    },
    "Virbox Protector": {
        "sopath":[], "soname":["ibvirbox32.so","libvirbox64.so"],
        "other":[], "soregex":[r"libvirbox.+\.so"], "jclass":[],
    },
    "Jiwei Security": {
        "sopath":["assets/ijm_lib/armeabi/libexec.so","assets/ijm_lib/X86/libexec.so",
                  "lib/armeabi/libexecmain.so"],
        "soname":["libexecmain.so","libexec.so"],
        "other":["assets/af.bin","assets/signed.bin","ijiami.dat"],
        "soregex":[], "jclass":[],
    },
    "Jiwei v3": {
        "sopath":[], "soname":["libexecv3.so"],
        "other":["assets/ijiami3.ajm"], "soregex":[], "jclass":[],
    },
    "Jiwei v5": {
        "sopath":["assets/libijmDataEncryption.so"],
        "soname":["libijmDataEncryption.so"], "other":["assets/IJMDal.Data"],
        "soregex":[], "jclass":[],
    },
    "Jiwei Enterprise": {
        "sopath":[], "soname":[], "other":["assets/ijiami.ajm"],
        "soregex":[], "jclass":[],
    },
    "Dingxiang (顶象)": {
        "sopath":["assets/libreincp.so","assets/libreincp_x86.so"],
        "soname":["libreincp.so","libreincp_x86.so"],
        "other":[], "soregex":[r"libreincp_.+\.so"], "jclass":[],
    },
    "NetEase Yidun": {
        "sopath":[], "soname":["libnesec.so"], "other":[], "soregex":[], "jclass":[],
    },
    "NetEase NQShield": {
        "sopath":[], "soname":["libnqshield.so"], "other":[], "soregex":[], "jclass":[],
    },
    "Baidu Protect": {
        "sopath":["lib/armeabi/libbaiduprotect.so"],
        "soname":["libbaiduprotect.so","libbaiduprotect_art.so","libbaiduprotect_x86.so"],
        "other":["assets/baiduprotect.jar","assets/baiduprotect1.jar"],
        "soregex":[], "jclass":[],
    },
    "Tencent VMP": {
        "sopath":["lib/arm64-v8a/libxgVipSecurity.so","lib/armeabi-v7a/libxgVipSecurity.so"],
        "soname":["libxgVipSecurity.so"], "other":[], "soregex":[], "jclass":[],
    },
    "Tencent Legu": {
        "sopath":["lib/armeabi/libshella-xxxx.so","lib/armeabi/libshellx-xxxx.so"],
        "soname":["liblegudb.so","libshel1x.so","libshell.so","libshella.so","libshellx.so","libtup.so"],
        "other":["lib/armeabi/mix.dex","lib/armeabi/mixz.dex","tencent_stub"],
        "soregex":[r"libshella-\d+\.\d+\.\d+\.\d+\.so"], "jclass":[],
    },
    "Tencent Legu Super": {
        "sopath":["assets/libshellx-super.2021.so","lib/armeabi/libshell-super.2019.so",
                  "lib/armeabi/libshell-super.2020.so","lib/armeabi/libshell-super.2021.so"],
        "soname":["libshell-super.2019.so","libshellx-super.2021.so"],
        "other":["tencent_sub"],
        "soregex":[r"libshellx-super\.\d+\.so", r"libshell-super\.\d+\.so"], "jclass":[],
    },
    "Tencent Legu Free": {
        "sopath":[], "soname":[],
        "other":["000000llllll.dex","00000ollllll.dex","000O00ll111l.dex",
                 "00O000ll111l.dex","0OO00l111l1l","o0oooOO0ooOo.dat"],
        "soregex":[], "jclass":[],
    },
    "Tencent Yuyun": {
        "sopath":["assets/libtosprotection.armeabi-v7a.so","assets/libtosprotection.armeabi.so",
                  "assets/libtosprotection.x86.so"],
        "soname":["libtosprotection.armeabi-v7a.so","libtosprotection.armeabi.so",
                  "libtosprotection.x86.so"],
        "other":["assets/tosversion"],
        "soregex":[r"libtosprotection\..+\.so"], "jclass":[],
    },
    "Tencent Shield": {
        "sopath":[], "soname":["libshell.so"], "other":[], "soregex":[], "jclass":[],
    },
    "Tencent Game": {
        "sopath":[], "soname":["libtprt.so"], "other":[], "soregex":[], "jclass":[],
    },
    "Haitun (海豚)": {
        "sopath":["assets/mxsafe/arm64-v8a/libdSafeShell.so","assets/mxsafe/x86_64/libdSafeShell.so"],
        "soname":["libdSafeShell.so","libmxacc.so"],
        "other":["assets/mxsafe.config","assets/mxsafe.data","assets/mxsafe.jar"],
        "soregex":[], "jclass":[],
    },
    "Alibaba Protect": {
        "sopath":[], "soname":["libNSaferOnly.so","libegis.so","libgeiri.so","libgeiri-x86.so"],
        "other":[], "soregex":[], "jclass":[],
    },
    "Alibaba Zuma": {
        "sopath":["assets/armeabi/libzuma.so","assets/libpreverify1.so","assets/libzuma.so"],
        "soname":["libzuma.so","libpreverify1.so","libmobisec.so","libsgmain.so","libsgsecuritybody.so"],
        "other":["aliprotect.dat"], "soregex":[], "jclass":[],
    },
    "Google Play Protect": {
        "sopath":["lib/arm64-v8a/libpairipcore.so","lib/armeabi-v7a/libpairipcore.so"],
        "soname":["libpairipcore.so"], "other":[], "soregex":[], "jclass":[],
    },
    "LIAPP": {
        "sopath":[], "soname":[],
        "other":["assets/LIAPP.ini","assets/pkgInfo.txt"],
        "soregex":[r"com\..+UnityDataAssetPack.+\.apk$", r"com\..+AddressablesAssetPack.+\.apk$"],
        "jclass":[],
    },
    "AppGuard (appguard.us)": {
        "sopath":[], "soname":["libloader.so"], "other":[],
        "soregex":[],
        "jclass":["AppGuard$IOnLoadInformation","AppGuard$VersionInformation",
                  "Lcom/nhent/appguard/AppGuard"],
    },
    "G-Presto": {
        "sopath":["lib/arm64-v8a/libATG_L.so"],
        "soname":["libATG_D.so","libATG_H.so","libATG_L.so"],
        "other":["assets/ATG_E.sec","assets/ATG_E_x64.sec"],
        "soregex":[],
        "jclass":["Lcom/bishopsoft/Presto","Presto_Init","ATG_H init"],
    },
    "APK Protect (desconhecido)": {
        "sopath":[], "soname":["libapk-protect.so"], "other":[], "soregex":[], "jclass":[],
    },
}

# --- Padroes de deteccao de seguranca ---
ROOT_FILE_PATTERNS = [
    ("/cache/.disable_magisk",          "Arquivo de desativacao do Magisk"),
    ("/cache/magisk.log",               "Log do Magisk"),
    ("/data/adb/ksu",                   "Diretorio do KernelSU"),
    ("/data/adb/magisk",                "Diretorio principal do Magisk"),
    ("/data/adb/magisk.db",             "Banco de dados do Magisk"),
    ("/data/local/bin/su",              "SU em caminho comum"),
    ("/data/local/su",                  "SU em caminho alternativo"),
    ("/data/local/xbin/su",             "SU do Xposed"),
    ("/dev/.magisk.unblock",            "Marcador de desbloqueio do Magisk"),
    ("/dev/com.koushikdutta.superuser.daemon/", "Socket do Superuser"),
    ("/init.magisk.rc",                 "Script de inicializacao do Magisk"),
    ("/sbin/.magisk",                   "Diretorio temporario do Magisk"),
    ("/sbin/su",                        "SU na particao do sistema"),
    ("/su/bin/su",                      "SU Systemless"),
    ("/system/app/Kinguser.apk",        "Kingroot instalado"),
    ("/system/app/Superuser.apk",       "Superuser instalado"),
    ("/system/bin/su",                  "SU nativo do sistema"),
    ("/system/xbin/busybox",            "BusyBox (associado a root)"),
    ("/system/xbin/daemonsu",           "Daemon do SuperSU"),
    ("/system/xbin/su",                 "SU em caminho comum"),
    ("/vendor/bin/su",                  "SU na particao vendor"),
    ("Kinguser.apk",                    "Kingroot (deteccao parcial)"),
    ("Superuser.apk",                   "Superuser (deteccao parcial)"),
]

ROOT_APP_PATTERNS = [
    ("com.topjohnwu.magisk",            "Magisk Manager"),
    ("eu.chainfire.supersu",            "Chainfire SuperSU"),
    ("me.weishu.kernelsu",              "KernelSU Manager"),
    ("com.kingroot.kinguser",           "KingRoot"),
    ("com.kingoapp.root",               "KingoRoot"),
    ("me.phh.superuser",                "PHH Superuser"),
    ("io.github.vvb2060.magisk",        "Magisk (variante)"),
    ("de.robv.android.xposed.installer","Xposed Installer"),
    ("org.meowcat.edxposed.manager",    "EdXposed Manager"),
    ("me.weishu.exp",                   "Taichi Framework"),
    ("com.speedsoftware.rootexplorer",  "Root Explorer"),
    ("com.keramidas.TitaniumBackup",    "Titanium Backup"),
    ("com.qihoo.root",                  "360 Root"),
    ("com.riru.core",                   "Riru Core"),
    ("com.alephzain.framaroot",         "Framaroot"),
    ("com.noshufou.android.su",         "Superuser oficial"),
    ("com.koushikdutta.superuser",      "Koush Superuser"),
    ("com.geohot.towelroot",            "Towelroot"),
]

EMULATOR_PATTERNS = [
    ("tel:123456",                      "Numero de telefone padrao do emulador"),
    ("test-keys",                       "Sistema com chaves de teste"),
    ("goldfish",                        "Kernel do emulador Android"),
    ("000000000000000",                 "IMEI padrao do emulador"),
    ("/dev/socket/qemud",               "Socket do daemon QEMU"),
    ("/dev/qemu_pipe",                  "Pipe de comunicacao QEMU"),
    ("ro.kernel.qemu",                  "Propriedade de kernel QEMU"),
    ("generic_x86",                     "ABI generica do emulador"),
    ("emulator",                        "Identificador de emulador"),
    ("ro.boot.virtual",                 "Boot virtualizado"),
    ("Build.HARDWARE=goldfish",         "Hardware do emulador"),
    ("Build.FINGERPRINT=generic",       "Fingerprint generica"),
    ("10.0.2.15",                       "IP NAT padrao do emulador"),
    ("eth0",                            "Interface de rede do emulador"),
    ("hasQemuSocket",                   "Funcao de deteccao de socket QEMU"),
    ("hasQemuPipe",                     "Funcao de deteccao de pipe QEMU"),
    ("getEmulatorQEMUKernel",           "Funcao de deteccao de kernel QEMU"),
]

DEBUG_PATTERNS = [
    ("checkFridaRunningProcesses",      "Deteccao de processos Frida"),
    ("de.robv.android.xposed.XposedBridge", "Deteccao do Xposed"),
    ("com.saurik.substrate.MS$2",       "Deteccao do Substrate"),
    ("Landroid/os/Debug;->isDebuggerConnected()Z", "Deteccao de debugger"),
    (":27042",                          "Porta padrao do Frida"),
    (":23946",                          "Porta de debug ADB"),
    ("frida-gadget",                    "Frida Gadget"),
    ("libfrida.so",                     "Biblioteca Frida"),
    ("XposedBridge.jar",                "Arquivo do Xposed"),
    ("frida-server",                    "Processo frida-server"),
    ("android_server",                  "Servidor de debug IDA"),
    ("gdbserver",                       "Servidor GDB"),
    ("ro.debuggable",                   "Propriedade de debug do sistema"),
    ("Magisk",                          "Deteccao do Magisk"),
    ("LSPosed",                         "Deteccao do LSPosed"),
    ("ptrace",                          "Deteccao de ptrace"),
    ("/proc/self/status",               "Deteccao de TracerPid"),
    ("sslunpinning",                    "Deteccao de SSL Unpinning"),
    ("JustTrustMe",                     "Modulo de bypass de certificado"),
]

PROXY_PATTERNS = [
    ("Lokhttp3/Proxy;->NO_PROXY:Lokhttp3/Proxy;",           "OkHttp desabilita proxy"),
    ("Lokhttp3/OkHttpClient$Builder;->proxy(",              "OkHttp configura proxy"),
    ("Lokhttp3/internal/proxy/NullProxySelector;",          "OkHttp seletor de proxy nulo"),
    ("Landroid/net/Proxy;->getDefaultProxy()",              "Obtem proxy padrao"),
    ("Landroid/net/Proxy;->getHost()",                      "Obtem host do proxy"),
    ("Landroid/net/Proxy;->getPort()",                      "Obtem porta do proxy"),
    ("Ljavax/net/ssl/X509TrustManager;",                    "TrustManager personalizado"),
    ("Ljavax/net/ssl/SSLContext;->init",                    "Inicializacao de contexto SSL"),
    ("VPNService",                                          "Deteccao de VPN"),
    ("NetworkCapabilities.TRANSPORT_VPN",                   "Capacidade de rede VPN"),
    ("isVpnUsed",                                           "Verificacao de uso de VPN"),
]

# --- Padroes de hardcode ---
HARDCODE_CATEGORIES = [
    ("Credenciais sensiveis", [
        r'(?i)password\s*=\s*[\'"][^\'"]{3,}[\'"]',
        r'(?i)passwd\s*=\s*[\'"][^\'"]{3,}[\'"]',
        r'(?i)secret\s*=\s*[\'"][^\'"]{3,}[\'"]',
        r'(?i)api[_-]?key\s*=\s*[\'"][^\'"]{3,}[\'"]',
        r'(?i)access[_-]?token\s*=\s*[\'"][^\'"]{3,}[\'"]',
        r'(?i)client_secret\s*=\s*[\'"][^\'"]{3,}[\'"]',
        r'(?i)auth\s*=\s*[\'"][^\'"]{3,}[\'"]',
    ]),
    ("Chaves privadas", [
        r'-----BEGIN RSA PRIVATE KEY-----',
        r'-----BEGIN EC PRIVATE KEY-----',
        r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
        r'-----BEGIN DSA PRIVATE KEY-----',
    ]),
    ("Tokens OAuth/JWT", [
        r'eyJhbGciOiJ',
        r'ya29\.[0-9A-Za-z\-_]+',
        r'EAACEdEose0cBA[0-9A-Za-z]+',
        r'access_token=[0-9a-zA-Z]+',
    ]),
    ("Credenciais de nuvem", [
        r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
        r'AIza[0-9A-Za-z\-_]{35}',
    ]),
    ("Chaves de pagamento", [
        r'sk_live_[0-9a-zA-Z]{24}',
        r'rk_live_[0-9a-zA-Z]{24}',
        r'sq0atp-[0-9A-Za-z\-_]{22}',
        r'sq0csp-[0-9A-Za-z\-_]{43}',
    ]),
    ("Tokens de plataformas", [
        r'[fF][aA][cC][eE][bB][oO][oO][kK].{0,20}[\'|"][0-9a-f]{32}[\'|"]',
        r'[gG][iI][tT][hH][uU][bB].{0,20}[\'|"][0-9a-zA-Z]{35,40}[\'|"]',
        r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}',
    ]),
    ("Outros segredos", [
        r'[sS][eE][cC][rR][eE][tT].{0,20}[\'|"][0-9a-zA-Z]{32,45}[\'|"]',
        r'[a-zA-Z]{3,10}://[^\s:@]{3,20}:[^\s:@]{3,20}@.{1,100}["\'\s]',
        r'SK[0-9a-fA-F]{32}',
    ]),
]

# --- Mapa de SDKs (soname -> label, team) ---
SDK_MAP = [
    ("libopencv_java3.so",          "OpenCV",                   "OpenCV"),
    ("libxamarin-app.so",           "Xamarin",                  "Microsoft"),
    ("libsqlite3requery.so",        "SQLite",                   "SQLite"),
    ("libmlkitcommonpipeline.so",   "ML Kit",                   "Google"),
    ("liblspd.so",                  "LSPatch",                  "LSPosed"),
    ("libappmodules.so",            "React Native",             "Facebook"),
    ("libreact_codegen_rncore.so",  "React Native",             "Facebook"),
    ("libruntimeexecutor.so",       "React Native",             "Facebook"),
    ("libglog_init.so",             "React Native",             "Facebook"),
    ("libhermes_executor.so",       "Hermes JS Engine",         "Facebook"),
    ("libyoga.so",                  "Yoga",                     "Facebook"),
    ("libyouga.so",                 "Yoga",                     "Facebook"),
    ("libunreal.so",                "Unreal Engine",            "Epic Games"),
    ("libmain.so",                  "Unity",                    "Unity Technologies"),
    ("libil2cpp.so",                "Unity IL2CPP",             "Unity Technologies"),
    ("libpanglepflipped.so",        "Pangle SDK",               "ByteDance"),
    ("liblynxdevtool.so",           "Lynx",                     "ByteDance"),
    ("libbytertc_ffmpeg_audio_extension.so", "BytePlus RTC",   "ByteDance"),
    ("libwechatns.so",              "Matrix",                   "Tencent"),
    ("libGCloudVoice.so",           "GVoice SDK",               "Tencent"),
    ("libTNN.so",                   "TNN",                      "Tencent"),
    ("libBugly.so",                 "Bugly",                    "Tencent"),
    ("libBugly-ext.so",             "Bugly",                    "Tencent"),
    ("libapmrt.so",                 "Tencent APM",              "Tencent"),
    ("libtxplayer.so",              "Tencent Video SDK",        "Tencent"),
    ("libqalcodecwrapper.so",       "Tencent Cloud IM SDK",     "Tencent"),
    ("libtdmqimei.so",              "Qimei SDK",                "Tencent"),
    ("libYoutuOcrJniApi.so",        "Tencent Youtu SDK",        "Tencent"),
    ("libagora_content_inspect_extension.so", "Agora RTC SDK", "Agora"),
    ("libRDTAPIsT.so",              "TUTK SDK",                 "TUTK"),
    ("libovpn3.so",                 "OpenVPN",                  "OpenVPN Inc."),
    ("libovpnexec.so",              "OpenVPN",                  "OpenVPN Inc."),
    ("libmonochrome_64.so",         "libmonochrome",            "Chromium"),
    ("libchrome_android_linker.so", "Android Crazy Linker",     "Chromium"),
    ("libwebviewchromium.huawei.so","HUAWEI WebView",           "Chromium/HUAWEI"),
    ("libMNN_dl.so",                "MNN",                      "Alibaba"),
    ("libMNNOpenCV.so",             "MNN",                      "Alibaba"),
    ("libMNN290.so",                "MNN",                      "Alibaba"),
    ("libsophix.so",                "Alibaba Mobile Hotfix",    "Aliyun"),
    ("libsls_producer.so",          "Log Service SLS",          "Aliyun"),
    ("libweex_xr_plugin.so",        "Weex",                     "Alibaba"),
    ("libtoyger.so",                "Auth SDK",                 "Alibaba"),
    ("libwtbt828.so",               "Amap SDK",                 "Alibaba"),
    ("libmpaasCrypto.so",           "mPaaS",                    "Alibaba"),
    ("libtaro_native_bridge.so",    "Taro",                     "JD"),
    ("libAliNNPython.so",           "AliNNPython",              "Alibaba"),
    ("libffmpeg_mediametadataretriever_jni.so", "FFmpeg",       "FFmpeg"),
    ("librxffmpeg-player.so",       "RxFFmpeg",                 "microshow"),
    ("libijkffmpeg.so",             "IJKPlayer",                "Bilibili"),
    ("libndkbitmap.so",             "Flame Barrage",            "Bilibili"),
    ("libvrtoolkit.so",             "Cardboard SDK",            "Google"),
    ("libglog.so",                  "glog",                     "Google"),
    ("libyuvutil.so",               "libYUV",                   "Google"),
    ("libYUVDecoder.so",            "libYUV",                   "Google"),
    ("libzucchini.so",              "Zucchini",                 "Google"),
    ("libmodft2.so",                "Pdfium",                   "Google"),
    ("libapplovinnative-crash-reporter.so", "AppLovin",         "AppLovin"),
    ("libpine.so",                  "Pine",                     "canyie"),
    ("libDexHelper-x86.so",         "Bangbang Security",        "Bangbang"),
    ("libfdog.so",                  "Naga Reinforcement",       "Naga"),
    ("libvdog-x86.so",              "Naga Reinforcement",       "Naga"),
    ("libnesec.so",                 "NetEase Yidun",            "Netease"),
    ("librtmp-jni.so",              "librtmp",                  "ant-media"),
    ("libmediastreamer_voip.so",    "Mediastreamer2",           "Belledonne"),
    ("libauth.so",                  "libauth",                  "Bitauth"),
    ("libkoom-native.so",           "KOOM",                     "KwaiAppTeam"),
    ("libOvenPlayerCore.so",        "OvenPlayer",               "AirenSoft"),
    ("libdrc.so",                   "libdrc",                   "Mema Hacking"),
    ("libp7zip.so",                 "AndroidP7zip",             "hzy3774"),
    ("libhwcpipe.so",               "HWCPipe",                  "ARM-software"),
    ("liblbtrtc.so",                "Lebo SDK",                 "Hpplay"),
    ("libDnsChecker.so",            "DnsChecker",               "olof"),
    ("libbd_facecollect_unifylicense.so", "Baidu Face Recognition", "Baidu"),
    ("libbd_etts.so",               "Baidu TTS SDK",            "Baidu"),
    ("libsnpe_adsp.so",             "SNPE SDK",                 "Qualcomm Snapdragon"),
    ("libstretch.so",               "Stretch",                  "vislyh"),
    ("libavif_android.so",          "libavif",                  "Alliance for Open Media"),
    ("libenet.so",                  "ENet",                     "Lee Salzman"),
    ("librongcloud_xcrash.so",      "RongCloud IM SDK",         "RongCloud"),
    ("libKF5ConfigQml_arm64-v8a.so","KDE Framework",            "KDE"),
    ("libandroid-tree-sitter.so",   "android-tree-sitter",      "AndroidIDEOfficial"),
    ("libSipCryptor.so",            "CFCA",                     "CFCA"),
    ("libcfcaMLog.so",              "CFCA",                     "CFCA"),
    ("libseenh_x86.so",             "CFCA Reinforcement",       "CFCA"),
    ("libP2PController.so",         "MobileIMSDK",              "JackJiang"),
    ("libduiutils.so",              "Sibiichi",                 "AISPEECH"),
    ("libnative-tianmu-common.so",  "Tianmu SDK",               "Tianmu"),
    ("libmpbase.so",                "Arcsoft",                  "Arcsoft"),
    ("libxray.so",                  "Xray Core",                "Project X"),
]

# --- Funcoes de scan ---

def scan_pack(apk):
    """Detecta protecoes/ofuscadores pelo conteudo do APK."""
    results = []
    names = [f.filename for f in apk.infolist()]
    name_set = set(names)

    compiled = {}
    for info in PACK_MAP.values():
        for pat in info.get("soregex", []):
            if pat not in compiled:
                try:
                    compiled[pat] = re.compile(pat)
                except re.error:
                    pass

    for packer, info in PACK_MAP.items():
        for sp in info.get("sopath", []):
            if sp in name_set:
                results.append("[sopath]  " + packer + "  ->  " + sp)
        for sn in info.get("soname", []):
            for n in names:
                if sn in n:
                    results.append("[soname]  " + packer + "  ->  " + n)
        for ot in info.get("other", []):
            for n in names:
                if ot in n:
                    results.append("[other]   " + packer + "  ->  " + n)
        for pat in info.get("soregex", []):
            rx = compiled.get(pat)
            if rx:
                for n in names:
                    if rx.search(n):
                        results.append("[regex]   " + packer + "  ->  " + n)
        for jc in info.get("jclass", []):
            if jc.startswith("//"):
                continue
            for f in apk.infolist():
                if not f.filename.endswith(".dex"):
                    continue
                try:
                    data = apk.read(f.filename)
                    if jc.encode() in data:
                        results.append("[jclass]  " + packer + "  ->  " + jc + "  (" + f.filename + ")")
                except Exception:
                    pass
    return results


def _scan_dex_patterns(data, filename, check_root, check_emu, check_debug, check_proxy):
    out = {"root": [], "emu": [], "debug": [], "proxy": []}
    if check_root:
        for pat, desc in ROOT_FILE_PATTERNS + ROOT_APP_PATTERNS:
            if pat.encode() in data:
                out["root"].append(filename + "  ->  " + pat + "  (" + desc + ")")
    if check_emu:
        for pat, desc in EMULATOR_PATTERNS:
            if pat.encode() in data:
                out["emu"].append(filename + "  ->  " + pat + "  (" + desc + ")")
    if check_debug:
        for pat, desc in DEBUG_PATTERNS:
            if pat.encode() in data:
                out["debug"].append(filename + "  ->  " + pat + "  (" + desc + ")")
    if check_proxy:
        for pat, desc in PROXY_PATTERNS:
            if pat.encode() in data:
                out["proxy"].append(filename + "  ->  " + pat + "  (" + desc + ")")
    return out


def scan_anti(apk, max_mb, check_root, check_emu, check_debug, check_proxy):
    """Varre todos os DEX em busca de padroes de seguranca."""
    combined = {"root": [], "emu": [], "debug": [], "proxy": []}
    limit = max_mb * 1024 * 1024
    for f in apk.infolist():
        if not f.filename.endswith(".dex"):
            continue
        try:
            data = apk.read(f.filename)[:limit]
            res = _scan_dex_patterns(data, f.filename, check_root, check_emu, check_debug, check_proxy)
            for k in combined:
                combined[k].extend(res[k])
        except Exception:
            pass
    return combined


def scan_sdk(apk):
    """Detecta SDKs de terceiros por nome de .so."""
    found = {}
    for f in apk.infolist():
        if not f.filename.endswith(".so"):
            continue
        for soname, label, team in SDK_MAP:
            if soname in f.filename:
                found.setdefault(team, [])
                entry = label + "  ->  " + f.filename
                if entry not in found[team]:
                    found[team].append(entry)
    return found


def _build_hardcode_patterns():
    patterns = []
    for cat, pats in HARDCODE_CATEGORIES:
        for p in pats:
            try:
                patterns.append((cat, re.compile(p.encode(), re.IGNORECASE)))
            except re.error:
                pass
    return patterns


def scan_hardcode(apk, max_mb):
    """Varre todos os arquivos em busca de hardcode."""
    patterns = _build_hardcode_patterns()
    limit = max_mb * 1024 * 1024
    results = {}
    seen = set()

    def _scan_file(info):
        local = {}
        try:
            data = apk.read(info.filename)[:limit]
        except Exception:
            return local
        for cat, rx in patterns:
            for m in rx.findall(data):
                text = m.decode("utf-8", errors="replace").strip()
                key = cat + "|" + text
                if key in seen:
                    continue
                seen.add(key)
                local.setdefault(cat, [])
                local[cat].append(info.filename + "  ->  " + text)
        return local

    files = apk.infolist()
    total = len(files)
    done = 0
    with ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(_scan_file, f): f for f in files}
        for fut in as_completed(futs):
            done += 1
            print("\r  Hardcode: " + str(done) + "/" + str(total), end="", flush=True)
            for cat, items in fut.result().items():
                results.setdefault(cat, [])
                results[cat].extend(items)
    print()
    return results


def scan_certificates(apk):
    """Extrai informacoes de certificados do APK."""
    CERT_EXTS = {".crt", ".cer", ".pem", ".der", ".p12", ".pfx", ".rsa", ".dsa"}
    results = []
    for f in apk.infolist():
        ext = Path(f.filename).suffix.lower()
        if ext not in CERT_EXTS:
            continue
        try:
            data = apk.read(f.filename)
            info = _parse_cert(data, f.filename)
            results.append(info)
        except Exception as e:
            results.append("  " + f.filename + "  ->  erro: " + str(e))
    return results


def _parse_cert(data, filename):
    lines = ["  Arquivo: " + filename]
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        import datetime
        cert = None
        if b"-----BEGIN" in data:
            try:
                cert = x509.load_pem_x509_certificate(data, default_backend())
            except Exception:
                pass
        if cert is None:
            try:
                cert = x509.load_der_x509_certificate(data, default_backend())
            except Exception:
                pass
        if cert:
            lines.append("    Assunto:    " + cert.subject.rfc4514_string())
            lines.append("    Emissor:    " + cert.issuer.rfc4514_string())
            lines.append("    Serie:      " + str(cert.serial_number))
            try:
                nb = cert.not_valid_before_utc
                na = cert.not_valid_after_utc
                now = datetime.datetime.now(datetime.timezone.utc)
            except AttributeError:
                nb = cert.not_valid_before
                na = cert.not_valid_after
                now = datetime.datetime.utcnow()
            lines.append("    Valido de:  " + nb.strftime("%Y-%m-%d %H:%M:%S"))
            lines.append("    Valido ate: " + na.strftime("%Y-%m-%d %H:%M:%S"))
            if na < now:
                lines.append("    [!] CERTIFICADO EXPIRADO")
        else:
            lines.append("    (nao foi possivel parsear o certificado)")
    except ImportError:
        lines.append("    (instale 'cryptography' para detalhes: pip install cryptography)")
    except Exception as e:
        lines.append("    erro: " + str(e))
    return "\n".join(lines)

# --- Saida formatada ---

def _print_section(title, items, empty_msg="Nenhum encontrado"):
    print(_sec(title))
    if items:
        for it in items:
            print(_item(it))
    else:
        print(_ok(empty_msg))


def _print_anti(results, check_root, check_emu, check_debug, check_proxy):
    print(_sec("Deteccao de seguranca (DEX)"))
    any_found = False
    if check_root and results["root"]:
        any_found = True
        print("    " + _Y + "ROOT" + _R)
        for r in results["root"]:
            print(_item(r))
    if check_emu and results["emu"]:
        any_found = True
        print("    " + _Y + "Emulador" + _R)
        for r in results["emu"]:
            print(_item(r))
    if check_debug and results["debug"]:
        any_found = True
        print("    " + _Y + "Anti-debug" + _R)
        for r in results["debug"]:
            print(_item(r))
    if check_proxy and results["proxy"]:
        any_found = True
        print("    " + _Y + "Proxy/SSL" + _R)
        for r in results["proxy"]:
            print(_item(r))
    if not any_found:
        print(_ok("Nenhum padrao de seguranca encontrado"))


def _print_sdk(results):
    print(_sec("SDKs de terceiros"))
    if not results:
        print(_ok("Nenhum SDK identificado"))
        return
    for team in sorted(results):
        print("    " + _C + team + _R)
        for item in sorted(results[team]):
            print(_item(item))


def _print_hardcode(results):
    print(_sec("Hardcode / Segredos"))
    if not results:
        print(_ok("Nenhum hardcode encontrado"))
        return
    total = sum(len(v) for v in results.values())
    print("    " + _Y + str(total) + " ocorrencia(s) em " + str(len(results)) + " categoria(s)" + _R)
    for cat in sorted(results):
        print("\n    " + _Y + cat + _R + "  (" + str(len(results[cat])) + ")")
        for it in results[cat]:
            print(_item(it))


# --- Logica principal ---

def scan_apk_data(apk, args, embedded=False):
    """Executa todos os scanners em um APK ja aberto."""
    pack = scan_pack(apk)
    print(_sec("Protecao / Ofuscacao"))
    if pack:
        for r in pack:
            print(_item(r))
    else:
        print(_ok("Nenhuma protecao detectada"))

    if args.root or args.emu or args.debug or args.proxy:
        anti = scan_anti(apk, args.maxsize, args.root, args.emu, args.debug, args.proxy)
        _print_anti(anti, args.root, args.emu, args.debug, args.proxy)

    if args.sdk:
        sdk = scan_sdk(apk)
        _print_sdk(sdk)

    if args.hardcode:
        hc = scan_hardcode(apk, args.maxsize)
        _print_hardcode(hc)

    if args.cert:
        certs = scan_certificates(apk)
        print(_sec("Certificados"))
        if certs:
            for c in certs:
                print(c)
        else:
            print(_ok("Nenhum certificado encontrado"))

    print()


def scan_apk_file(filepath, args):
    """Abre e escaneia um arquivo APK."""
    print("\n" + _C + _BD + "=" * 70 + _R)
    print(_C + _BD + "  APK: " + filepath + _R)
    print(_C + "=" * 70 + _R)
    try:
        with zipfile.ZipFile(filepath, "r") as apk:
            scan_apk_data(apk, args, embedded=False)
            if args.recursive:
                for f in apk.infolist():
                    if not f.filename.endswith(".apk"):
                        continue
                    print("\n  " + _Y + "[APK embutido]" + _R + " " + f.filename)
                    try:
                        limit = args.maxsize * 1024 * 1024
                        data = apk.read(f.filename)[:limit]
                        with zipfile.ZipFile(io.BytesIO(data)) as inner:
                            scan_apk_data(inner, args, embedded=True)
                    except Exception as e:
                        print("  " + _RE + "Erro ao processar APK embutido: " + str(e) + _R)
    except zipfile.BadZipFile:
        print("  " + _RE + "Erro: arquivo nao e um APK/ZIP valido." + _R)
    except Exception as e:
        print("  " + _RE + "Erro: " + str(e) + _R)


def scan_folder(folder, args):
    """Escaneia todos os APKs em uma pasta."""
    apks = list(Path(folder).rglob("*.apk"))
    if not apks:
        print(_Y + "Nenhum APK encontrado em: " + folder + _R)
        return
    print(_C + "Encontrado(s) " + str(len(apks)) + " APK(s) em " + folder + _R)
    for apk_path in apks:
        scan_apk_file(str(apk_path), args)


# --- Funcao de integracao com NoxDroid ---

def run_apk_check(filepath,
                  check_root=True, check_emu=True, check_debug=True, check_proxy=True,
                  check_sdk=True, check_hardcode=False, check_cert=True,
                  max_mb=500, recursive=True):
    """
    Ponto de entrada para uso dentro do NoxDroid.
    Pode ser chamado de qualquer modulo sem precisar do argparse.
    """
    os.system("")  # habilita ANSI no Windows

    class _Args:
        pass

    args = _Args()
    args.root      = check_root
    args.emu       = check_emu
    args.debug     = check_debug
    args.proxy     = check_proxy
    args.sdk       = check_sdk
    args.hardcode  = check_hardcode
    args.cert      = check_cert
    args.maxsize   = max_mb
    args.recursive = recursive
    p = Path(filepath)
    if p.is_dir():
        scan_folder(str(p), args)
    elif p.is_file():
        scan_apk_file(str(p), args)
    else:
        print(_RE + "Caminho invalido: " + filepath + _R)


# --- CLI standalone ---

def _cli():
    os.system("")
    parser = argparse.ArgumentParser(
        prog="apk_check",
        description="APK Check - Analisador de APK Android",
    )
    parser.add_argument("-f", "--file",      required=True,
                        help="Caminho para o APK ou pasta com APKs")
    parser.add_argument("--root",            action=argparse.BooleanOptionalAction,
                        default=True,        help="Detectar ROOT (padrao: ativo)")
    parser.add_argument("--emu",             action=argparse.BooleanOptionalAction,
                        default=True,        help="Detectar emulador (padrao: ativo)")
    parser.add_argument("--debug",           action=argparse.BooleanOptionalAction,
                        default=True,        help="Detectar anti-debug (padrao: ativo)")
    parser.add_argument("--proxy",           action=argparse.BooleanOptionalAction,
                        default=True,        help="Detectar proxy/SSL (padrao: ativo)")
    parser.add_argument("--sdk",             action=argparse.BooleanOptionalAction,
                        default=True,        help="Detectar SDKs (padrao: ativo)")
    parser.add_argument("--hardcode",        action=argparse.BooleanOptionalAction,
                        default=False,       help="Detectar hardcode (padrao: inativo)")
    parser.add_argument("--cert",            action=argparse.BooleanOptionalAction,
                        default=True,        help="Analisar certificados (padrao: ativo)")
    parser.add_argument("--maxsize",         type=int, default=500,
                        help="Tamanho maximo de arquivo a escanear em MB (padrao: 500)")
    parser.add_argument("--recursive", "-r", action=argparse.BooleanOptionalAction,
                        default=True,        help="Escanear APKs embutidos (padrao: ativo)")

    args = parser.parse_args()

    class _Args:
        root      = args.root
        emu       = args.emu
        debug     = args.debug
        proxy     = args.proxy
        sdk       = args.sdk
        hardcode  = args.hardcode
        cert      = args.cert
        maxsize   = args.maxsize
        recursive = args.recursive

    print("\n" + _C + _BD + "APK Check - Configuracao" + _R)
    print("  Arquivo : " + args.file)
    print("  Checks  : root=" + str(args.root) + " emu=" + str(args.emu) +
          " debug=" + str(args.debug) + " proxy=" + str(args.proxy) +
          " sdk=" + str(args.sdk) + " hardcode=" + str(args.hardcode) +
          " cert=" + str(args.cert))
    print("  Max MB  : " + str(args.maxsize) + "  |  Recursivo: " + str(args.recursive))
    print("  " + _D + "-" * 60 + _R)

    p = Path(args.file)
    a = _Args()
    if p.is_dir():
        scan_folder(str(p), a)
    elif p.is_file():
        scan_apk_file(str(p), a)
    else:
        print(_RE + "Caminho invalido: " + args.file + _R)
        sys.exit(1)


if __name__ == "__main__":
    _cli()

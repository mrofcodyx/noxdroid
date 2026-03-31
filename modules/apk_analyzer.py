"""
APK Analyzer — análise estática de APKs Android.
Funcionalidades:
  - Decompilação via apktool (smali) e jadx (Java)
  - Detecção de Certificate Pinning
  - Detecção de Root Detection
  - Detecção de Anti-Debug / Anti-Tamper
  - Detecção de dados sensíveis hardcoded
  - Extração de Custom URLs do AndroidManifest.xml
  - Download de APK do dispositivo por package name
  - Resultados salvos em results/<pkg>/analysis/<timestamp>/
"""
import os
import re
import json
import subprocess
import shutil
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

_RESET  = "\033[0m"
_CYAN   = "\033[96m"
_WHITE  = "\033[97m"
_DIM    = "\033[90m"
_BOLD   = "\033[1m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_GREEN  = "\033[92m"

RESULTS_DIR = Path("results")

# ─── Padrões de análise ───────────────────────────────────────────────────────

PINNING_PATTERNS = {
    # ── OkHttp ──────────────────────────────────────────────────────────────
    "OkHttp / CertificatePinner": [
        r"Lokhttp3/CertificatePinner",
        r"Lokhttp3/CertificatePinner\$Builder",
        r"okhttp3/CertificatePinner",
        r"\.addCertificatePinner\(",
        r"CertificatePinner\.Builder\(\)",
        r"Lokhttp3/internal/tls/",
        r"Lokhttp3/ConnectionSpec",
        r"HandshakeCertificates",
        r"HeldCertificate",
    ],
    # ── Retrofit ────────────────────────────────────────────────────────────
    "Retrofit / Interceptor": [
        r"Lretrofit2/Retrofit\$Builder",
        r"Lretrofit2/OkHttpCall",
        r"addInterceptor\(.*ssl",
        r"addNetworkInterceptor\(.*ssl",
        r"Lokhttp3/Interceptor",
        r"HttpLoggingInterceptor",
    ],
    # ── TrustManager customizado ─────────────────────────────────────────────
    "TrustManager Customizado": [
        r"Ljavax/net/ssl/X509TrustManager",
        r"implements.*X509TrustManager",
        r"\.method public checkServerTrusted",
        r"\.method public checkClientTrusted",
        r"\.method public getAcceptedIssuers",
        r"Ljavax/net/ssl/TrustManagerFactory",
        r"Ljavax/net/ssl/KeyManagerFactory",
        r"KeyStore->getInstance",
        r'\.bks["\'\s]',
        r'\.p12["\'\s]',
        r'\.pfx["\'\s]',
    ],
    # ── SSLContext / SocketFactory ───────────────────────────────────────────
    "SSLContext / SSLSocketFactory": [
        r"Ljavax/net/ssl/SSLContext;->init\(",
        r"Ljavax/net/ssl/SSLContext;->getInstance\(",
        r"Ljavax/net/ssl/SSLSocketFactory",
        r"ALLOW_ALL_HOSTNAME_VERIFIER",
        r"NullHostnameVerifier",
        r"AllowAllHostnameVerifier",
        r"\.method.*HostnameVerifier.*verify\(",
        r"SSLSocketFactory\.getInsecure\(",
    ],
    # ── WebView SSL inseguro ─────────────────────────────────────────────────
    "WebView SSL Inseguro": [
        r"\.method.*onReceivedSslError\(",
        r"Landroid/webkit/SslErrorHandler;->proceed\(\)",
        r"setWebContentsDebuggingEnabled.*true",
        r"MIXED_CONTENT_ALWAYS_ALLOW",
    ],
    # ── Hash Pinning ─────────────────────────────────────────────────────────
    "Hash Pinning (SHA256/SHA1)": [
        r"sha256/[A-Za-z0-9+/=]{44}",
        r"sha1/[A-Za-z0-9+/=]{28}",
        r"getPublicKey\(\)->getEncoded\(\)",
        r"MessageDigest;->getInstance.*SHA-256",
    ],
    # ── Network Security Config ──────────────────────────────────────────────
    "Network Security Config": [
        r"android:networkSecurityConfig",
        r"<pin-set",
        r'<pin digest=',
        r"<trust-anchors",
        r'cleartextTrafficPermitted="false"',
    ],
    # ── Volley ───────────────────────────────────────────────────────────────
    "Volley / HurlStack": [
        r"Lcom/android/volley/toolbox/HurlStack",
        r"Lcom/android/volley/toolbox/Volley",
        r"HurlStack.*SSLSocketFactory",
    ],
    # ── Conscrypt ────────────────────────────────────────────────────────────
    "Conscrypt": [
        r"Lorg/conscrypt/Conscrypt",
        r"Conscrypt\.newProvider\(\)",
        r"Security\.insertProviderAt.*Conscrypt",
    ],
    # ── gRPC / Cronet ────────────────────────────────────────────────────────
    "gRPC / Cronet TLS": [
        r"Lio/grpc/.*ChannelBuilder",
        r"Lorg/chromium/net/CronetEngine",
        r"useTransportSecurity\(",
        r"\.sslContext\(",
    ],
    # ── Flutter ──────────────────────────────────────────────────────────────
    "Flutter / Dart TLS": [
        r"HttpClient.*badCertificateCallback",
        r"onBadCertificate",
        r"SecurityContext\(\)",
    ],
}

ROOT_PATTERNS = {
    # ── Binários su ──────────────────────────────────────────────────────────
    "Root Binaries": [
        r'const-string.*"/system/bin/su"',
        r'const-string.*"/system/xbin/su"',
        r'const-string.*"/system/xbin/busybox"',
        r'const-string.*"/sbin/su"',
        r'const-string.*"/su/bin/su"',
        r'const-string.*"/vendor/bin/su"',
        r'const-string.*"/data/local/bin/su"',
        r'const-string.*"/data/local/xbin/su"',
        r'const-string.*"/system/bin/failsafe/su"',
        r'const-string.*"which su"',
    ],
    # ── Package names de apps root ───────────────────────────────────────────
    "Root Management Apps": [
        r'const-string.*"com\.topjohnwu\.magisk"',
        r'const-string.*"eu\.chainfire\.supersu"',
        r'const-string.*"me\.weishu\.kernelsu"',
        r'const-string.*"com\.kingroot\.kinguser"',
        r'const-string.*"com\.kingoapp\.root"',
        r'const-string.*"me\.phh\.superuser"',
        r'const-string.*"com\.noshufou\.android\.su"',
        r'const-string.*"com\.koushikdutta\.superuser"',
        r'const-string.*"com\.riru\.core"',
        r'const-string.*"de\.robv\.android\.xposed\.installer"',
        r'const-string.*"org\.meowcat\.edxposed\.manager"',
        r'const-string.*"me\.weishu\.exp"',
        r'const-string.*"com\.saurik\.substrate"',
    ],
    # ── Bibliotecas de detecção ──────────────────────────────────────────────
    "Root Detection Libraries": [
        r"Lcom/scottyab/rootbeer/RootBeer",
        r"scottyab/rootbeer",
        r"RootCloak",
        r"\.method.*isRooted\(\)Z",
        r"\.method.*isDeviceRooted\(\)Z",
        r"\.method.*checkRootMethod",
        r"\.method.*detectRoot",
        r"\.method.*checkForSuperUser",
        r"\.method.*checkForBusyBox",
        r"\.method.*checkForDangerousProps",
        r"\.method.*checkSuExists",
        r"\.method.*findBinary",
    ],
    # ── Propriedades do sistema ──────────────────────────────────────────────
    "System Properties": [
        r'const-string.*"ro\.debuggable"',
        r'const-string.*"ro\.secure"',
        r'const-string.*"ro\.build\.tags"',
        r'const-string.*"test-keys"',
        r'const-string.*"ro\.build\.type"',
        r'const-string.*"ro\.build\.selinux"',
        r"android/os/SystemProperties;->get\(",
    ],
    # ── Caminhos suspeitos ───────────────────────────────────────────────────
    "Unsafe Paths": [
        r'const-string.*"/data/adb/magisk"',
        r'const-string.*"/data/adb/ksu"',
        r'const-string.*"/sbin/\.magisk"',
        r'const-string.*"/cache/magisk\.log"',
        r'const-string.*"/init\.magisk\.rc"',
        r'const-string.*"/system/app/Superuser"',
        r'const-string.*"/system/app/SuperSU"',
        r'const-string.*"/proc/self/maps"',
        r'const-string.*"/proc/net/tcp"',
    ],
    # ── SELinux ──────────────────────────────────────────────────────────────
    "SELinux": [
        r"Landroid/os/SELinux;->isSELinuxEnabled\(\)",
        r"Landroid/os/SELinux;->isSELinuxEnforced\(\)",
        r"\.method.*isSELinuxEnforced",
        r"\.method.*getSelinuxEnforceMode",
    ],
    # ── Play Integrity / SafetyNet ───────────────────────────────────────────
    "Play Integrity / SafetyNet": [
        r"Lcom/google/android/play/core/integrity/IntegrityManager",
        r"Lcom/google/android/play/core/integrity/IntegrityTokenRequest",
        r"Lcom/google/android/gms/safetynet/SafetyNet",
        r"Lcom/google/android/gms/safetynet/SafetyNetClient",
        r"SafetyNetApi\.attest\(",
        r"setAttestationChallenge\(",
        r"Landroid/security/keystore/KeyGenParameterSpec",
    ],
    # ── Xposed / LSPosed / Frida ─────────────────────────────────────────────
    "Xposed / LSPosed / Frida": [
        r"Lde/robv/android/xposed/XposedBridge",
        r"Lde/robv/android/xposed/XposedHelpers",
        r'const-string.*"XposedBridge\.jar"',
        r"Lorg/lsposed",
        r"Lio/github/lsposed",
        r'const-string.*"frida-gadget"',
        r'const-string.*"frida-server"',
        r'const-string.*"libfrida"',
        r'const-string.*":27042"',
        r"checkFridaRunningProcesses",
        r"Lcom/saurik/substrate/MS",
    ],
    # ── Detecção de emulador ─────────────────────────────────────────────────
    "Emulator Detection": [
        r'const-string.*"goldfish"',
        r'const-string.*"ranchu"',
        r'const-string.*"generic_x86"',
        r'const-string.*"Genymotion"',
        r'const-string.*"/dev/socket/qemud"',
        r'const-string.*"/dev/qemu_pipe"',
        r'const-string.*"ro\.kernel\.qemu"',
        r"\.method.*isEmulator\(\)",
        r"\.method.*isRunningOnEmulator",
        r"\.method.*checkEmulator",
    ],
}

# ─── Anti-Debug / Anti-Tamper ─────────────────────────────────────────────────

ANTIDEBUG_PATTERNS = {
    # ── Detecção de debugger ─────────────────────────────────────────────────
    "Debugger Detection": [
        r"Landroid/os/Debug;->isDebuggerConnected\(\)Z",
        r"Landroid/os/Debug;->waitForDebugger\(\)V",
        r"\.method.*isDebuggerConnected\(\)",
        r'const-string.*"TracerPid"',
        r'const-string.*"/proc/self/status"',
        r'const-string.*"PTRACE_TRACEME"',
        r'const-string.*"android_server"',
        r'const-string.*"gdbserver"',
    ],
    # ── Flag debuggable ──────────────────────────────────────────────────────
    "Debuggable Flag": [
        r'android:debuggable="true"',
        r"Landroid/content/pm/ApplicationInfo;->FLAG_DEBUGGABLE",
        r"getApplicationInfo\(\)\.flags.*FLAG_DEBUGGABLE",
    ],
    # ── Verificação de assinatura / integridade ──────────────────────────────
    "APK Signature / Integrity": [
        r"GET_SIGNATURES",
        r"GET_SIGNING_CERTIFICATES",
        r"Landroid/content/pm/PackageInfo;->signatures",
        r"Landroid/content/pm/Signature;->toCharsString\(\)",
        r"\.method.*verifySignature",
        r"\.method.*checkSignature",
        r"getInstallerPackageName\(",
    ],
    # ── Hook / instrumentação ────────────────────────────────────────────────
    "Hook / Instrumentation Detection": [
        r"Ldalvik/system/DexClassLoader",
        r"Ldalvik/system/PathClassLoader",
        r"\.method.*findLoadedClass\(",
        r"ActivityThread;->currentActivityThread\(\)",
        r"\.method.*getInstrumentation\(\)",
        r"Landroid/app/ActivityThread;->mInstrumentation",
    ],
    # ── Leitura de /proc/maps ────────────────────────────────────────────────
    "Memory / Maps Inspection": [
        r'const-string.*"/proc/self/maps"',
        r'const-string.*"/proc/self/mem"',
        r"\.method.*readMaps\(",
        r"\.method.*mapsContains",
        r"\.method.*checkMaps",
    ],
    # ── Proteção de tela ─────────────────────────────────────────────────────
    "Screenshot Protection (FLAG_SECURE)": [
        r"WindowManager\$LayoutParams;->FLAG_SECURE",
        r"setFlags.*FLAG_SECURE",
        r"addFlags.*FLAG_SECURE",
        r"LayoutParams\.FLAG_SECURE",
    ],
    # ── Detecção de VPN / proxy ──────────────────────────────────────────────
    "VPN / Proxy Detection": [
        r"Landroid/net/VpnService",
        r"NetworkCapabilities;->TRANSPORT_VPN",
        r"\.method.*isVpnUsed\(",
        r'const-string.*"http\.proxyHost"',
        r'const-string.*"http\.proxyPort"',
        r"Landroid/net/Proxy;->getDefaultHost\(",
        r"Landroid/net/Proxy;->getDefaultPort\(",
    ],
}

# ─── Dados sensíveis hardcoded — carregados de curated.json ──────────────────
# Mantemos HARDCODE_PATTERNS como fallback caso o JSON não seja encontrado.

HARDCODE_PATTERNS = {
    "AWS Credentials": [
        r'(?:AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\'][^"\']{20,}["\']',
    ],
    "Chaves Privadas": [
        r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
        r'-----BEGIN PGP PRIVATE KEY BLOCK-----',
    ],
    "Chaves de Pagamento": [
        r'sk_live_[0-9a-zA-Z]{24}',
        r'sq0csp-[0-9A-Za-z\-_]{43}',
    ],
    "JWT / OAuth Tokens": [
        r'eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_.+/=]{10,}',
        r'ya29\.[0-9A-Za-z\-_]{30,}',
    ],
}

# ─── Crypto Misuse ────────────────────────────────────────────────────────────

CRYPTO_MISUSE_PATTERNS = {
    # ── Algoritmos fracos ────────────────────────────────────────────────────
    "Algoritmos Fracos (MD5/SHA1/DES/RC4)": [
        r'MessageDigest;->getInstance.*"MD5"',
        r'MessageDigest;->getInstance.*"SHA-1"',
        r'MessageDigest;->getInstance.*"SHA1"',
        r'Cipher;->getInstance.*"DES[^A-Z]',
        r'Cipher;->getInstance.*"DES/ECB',
        r'Cipher;->getInstance.*"RC4"',
        r'Cipher;->getInstance.*"RC2"',
        r'Cipher;->getInstance.*"Blowfish"',
        r'const-string.*"MD5"',
        r'const-string.*"DES"',
        r'const-string.*"RC4"',
        r'const-string.*"SHA-1"',
    ],
    # ── Modo ECB (sem IV) ────────────────────────────────────────────────────
    "Modo ECB (sem IV — determinístico)": [
        r'Cipher;->getInstance.*"AES/ECB',
        r'Cipher;->getInstance.*"DES/ECB',
        r'Cipher;->getInstance.*"RSA/ECB',
        r'const-string.*"AES/ECB',
        r'const-string.*"DES/ECB',
        r'const-string.*"/ECB/',
    ],
    # ── IV / Key hardcoded ───────────────────────────────────────────────────
    "IV / Key Hardcoded": [
        r'IvParameterSpec;-><init>.*\[B',
        r'SecretKeySpec;-><init>.*\[B',
        r'const-string.*"[0-9a-fA-F]{32}"',   # 128-bit hex key
        r'const-string.*"[0-9a-fA-F]{64}"',   # 256-bit hex key
        r'const-string.*"[A-Za-z0-9+/=]{24}"',# 128-bit base64 key
        r'new-array.*\[B.*0x10',               # byte[16] — possível AES key
        r'new-array.*\[B.*0x20',               # byte[32]
        r'\.field.*\[B.*=.*{',                 # campo byte[] inicializado inline
    ],
    # ── Random inseguro ──────────────────────────────────────────────────────
    "Random Inseguro (java.util.Random)": [
        r'Ljava/util/Random;-><init>\(\)',
        r'Ljava/util/Random;->nextInt\(',
        r'Ljava/util/Random;->nextBytes\(',
        r'Ljava/util/Random;->nextLong\(',
        r'new-instance.*Ljava/util/Random',
        r'import java\.util\.Random',
        r'new Random\(\)',
    ],
    # ── Padding Oracle ───────────────────────────────────────────────────────
    "Padding Inseguro (PKCS5/PKCS7 sem autenticação)": [
        r'Cipher;->getInstance.*"AES/CBC/PKCS5Padding"',
        r'Cipher;->getInstance.*"AES/CBC/PKCS7Padding"',
        r'const-string.*"AES/CBC/PKCS5Padding"',
        r'const-string.*"AES/CBC/PKCS7Padding"',
    ],
    # ── Sem autenticação (GCM ausente) ───────────────────────────────────────
    "Criptografia sem Autenticação (não-GCM)": [
        r'Cipher;->getInstance.*"AES/CBC',
        r'Cipher;->getInstance.*"AES/CTR',
        r'Cipher;->getInstance.*"AES/CFB',
        r'Cipher;->getInstance.*"AES/OFB',
    ],
}

# ─── WebView / JavaScript Interface ──────────────────────────────────────────

WEBVIEW_PATTERNS = {
    # ── addJavascriptInterface ───────────────────────────────────────────────
    "addJavascriptInterface (XSS → RCE)": [
        r'addJavascriptInterface\(',
        r'Landroid/webkit/WebView;->addJavascriptInterface\(',
        r'\.method.*addJavascriptInterface',
    ],
    # ── File Access ──────────────────────────────────────────────────────────
    "setAllowFileAccess / Universal Access": [
        r'setAllowFileAccess\(.*true',
        r'setAllowUniversalAccessFromFileURLs\(.*true',
        r'setAllowFileAccessFromFileURLs\(.*true',
        r'Landroid/webkit/WebSettings;->setAllowFileAccess\(',
        r'Landroid/webkit/WebSettings;->setAllowUniversalAccessFromFileURLs\(',
    ],
    # ── JavaScript habilitado ────────────────────────────────────────────────
    "setJavaScriptEnabled(true)": [
        r'setJavaScriptEnabled\(.*true',
        r'Landroid/webkit/WebSettings;->setJavaScriptEnabled\(',
    ],
    # ── loadUrl com dados externos ───────────────────────────────────────────
    "loadUrl / evaluateJavascript com dados externos": [
        r'Landroid/webkit/WebView;->loadUrl\(',
        r'Landroid/webkit/WebView;->evaluateJavascript\(',
        r'Landroid/webkit/WebView;->loadDataWithBaseURL\(',
        r'\.method.*loadUrl\(',
        r'evaluateJavascript\(',
    ],
    # ── WebView debugging ────────────────────────────────────────────────────
    "WebView Debugging habilitado": [
        r'setWebContentsDebuggingEnabled\(.*true',
        r'WebView\.setWebContentsDebuggingEnabled\(',
    ],
    # ── shouldOverrideUrlLoading ausente ─────────────────────────────────────
    "shouldOverrideUrlLoading (Open Redirect)": [
        r'shouldOverrideUrlLoading',
        r'Landroid/webkit/WebViewClient;->shouldOverrideUrlLoading\(',
    ],
}

# ─── Insecure IPC / Intent ────────────────────────────────────────────────────

INSECURE_IPC_PATTERNS = {
    # ── Pending Intent mutável ───────────────────────────────────────────────
    "PendingIntent Mutável (FLAG_MUTABLE)": [
        r'PendingIntent\.FLAG_MUTABLE',
        r'Landroid/app/PendingIntent;->FLAG_MUTABLE',
        r'getActivity.*FLAG_MUTABLE',
        r'getBroadcast.*FLAG_MUTABLE',
        r'getService.*FLAG_MUTABLE',
    ],
    # ── Intent implícito com dados sensíveis ─────────────────────────────────
    "Intent Implícito (sem componente explícito)": [
        r'new-instance.*Landroid/content/Intent;',
        r'Intent;-><init>\(Ljava/lang/String;\)',
        r'sendBroadcast\(.*intent',
        r'startActivity\(.*intent',
        r'startService\(.*intent',
    ],
    # ── Sticky Broadcast ─────────────────────────────────────────────────────
    "Sticky Broadcast (deprecated + inseguro)": [
        r'sendStickyBroadcast\(',
        r'Landroid/content/Context;->sendStickyBroadcast\(',
        r'sendStickyOrderedBroadcast\(',
    ],
    # ── Clipboard com dados sensíveis ────────────────────────────────────────
    "ClipboardManager (dados sensíveis)": [
        r'Landroid/content/ClipboardManager;->setPrimaryClip\(',
        r'ClipData\.newPlainText\(',
        r'setPrimaryClip\(',
    ],
    # ── Broadcast sem permissão ──────────────────────────────────────────────
    "sendBroadcast sem permissão": [
        r'sendBroadcast\(.*\)V',
        r'Landroid/content/Context;->sendBroadcast\(Landroid/content/Intent;\)V',
    ],
}

# ─── Dynamic Code Loading / Reflection ───────────────────────────────────────

DYNAMIC_CODE_PATTERNS = {
    # ── DexClassLoader ───────────────────────────────────────────────────────
    "DexClassLoader / PathClassLoader": [
        r'Ldalvik/system/DexClassLoader;-><init>\(',
        r'Ldalvik/system/PathClassLoader;-><init>\(',
        r'Ldalvik/system/InMemoryDexClassLoader',
        r'new-instance.*DexClassLoader',
        r'new-instance.*PathClassLoader',
        r'new-instance.*InMemoryDexClassLoader',
    ],
    # ── Reflection ───────────────────────────────────────────────────────────
    "Reflection (Class.forName / invoke)": [
        r'Ljava/lang/Class;->forName\(',
        r'Ljava/lang/reflect/Method;->invoke\(',
        r'Ljava/lang/reflect/Field;->get\(',
        r'Ljava/lang/reflect/Field;->set\(',
        r'Class\.forName\(',
        r'getDeclaredMethod\(',
        r'getDeclaredField\(',
        r'setAccessible\(.*true',
    ],
    # ── Carregamento de código nativo ────────────────────────────────────────
    "System.loadLibrary / load": [
        r'Ljava/lang/System;->loadLibrary\(',
        r'Ljava/lang/System;->load\(',
        r'Runtime;->loadLibrary\(',
        r'System\.loadLibrary\(',
        r'System\.load\(',
    ],
    # ── Execução de código dinâmico ──────────────────────────────────────────
    "Execução Dinâmica (eval / script engine)": [
        r'Ljavax/script/ScriptEngine;->eval\(',
        r'ScriptEngine.*eval\(',
        r'Lorg/mozilla/javascript',
        r'Lcom/eclipsesource/v8',
        r'Lj2v8',
    ],
}

# ─── Command Injection / Path Traversal ──────────────────────────────────────

INJECTION_PATTERNS = {
    # ── Runtime.exec ─────────────────────────────────────────────────────────
    "Runtime.exec / ProcessBuilder (Command Injection)": [
        r'Ljava/lang/Runtime;->exec\(',
        r'Ljava/lang/ProcessBuilder;-><init>\(',
        r'Runtime\.getRuntime\(\)\.exec\(',
        r'new ProcessBuilder\(',
        r'new-instance.*ProcessBuilder',
        r'exec\(.*getIntent\(',
        r'exec\(.*getExtra\(',
    ],
    # ── Path Traversal ───────────────────────────────────────────────────────
    "Path Traversal (FileInputStream/FileOutputStream)": [
        r'Ljava/io/FileInputStream;-><init>\(Ljava/lang/String;\)',
        r'Ljava/io/FileOutputStream;-><init>\(Ljava/lang/String;\)',
        r'Ljava/io/File;-><init>\(Ljava/lang/String;Ljava/lang/String;\)',
        r'new FileInputStream\(',
        r'new FileOutputStream\(',
        r'openFileOutput\(',
        r'openFileInput\(',
        r'getFilesDir\(\)',
        r'getCacheDir\(\)',
    ],
    # ── SQL Injection ─────────────────────────────────────────────────────────
    "SQL Injection (rawQuery / execSQL)": [
        r'Landroid/database/sqlite/SQLiteDatabase;->rawQuery\(',
        r'Landroid/database/sqlite/SQLiteDatabase;->execSQL\(',
        r'rawQuery\(',
        r'execSQL\(',
        r'\.query\(.*\+',   # concatenação de string em query
        r'rawQuery\(.*\+',
    ],
    # ── XML / JSON Injection ──────────────────────────────────────────────────
    "XML External Entity (XXE)": [
        r'DocumentBuilderFactory;->newInstance\(',
        r'SAXParserFactory;->newInstance\(',
        r'XMLInputFactory;->newInstance\(',
        r'setFeature.*external-general-entities.*true',
        r'setFeature.*external-parameter-entities.*true',
        r'setExpandEntityReferences\(.*true',
    ],
}

# ─── Insecure Serialization ───────────────────────────────────────────────────

SERIALIZATION_PATTERNS = {
    # ── ObjectInputStream ────────────────────────────────────────────────────
    "ObjectInputStream (Desserialização insegura)": [
        r'Ljava/io/ObjectInputStream;-><init>\(',
        r'Ljava/io/ObjectInputStream;->readObject\(',
        r'new ObjectInputStream\(',
        r'readObject\(\)',
        r'readUnshared\(\)',
    ],
    # ── Serializable sem validação ───────────────────────────────────────────
    "Serializable / Parcelable sem validação": [
        r'implements Serializable',
        r'Ljava/io/Serializable',
        r'Landroid/os/Parcelable',
        r'createFromParcel\(',
        r'readFromParcel\(',
        r'Parcel;->readString\(\)',
        r'Parcel;->readInt\(\)',
    ],
    # ── Gson / Jackson sem type adapter ──────────────────────────────────────
    "Gson / Jackson (deserialização polimórfica)": [
        r'Lcom/google/gson/Gson;->fromJson\(',
        r'Lcom/fasterxml/jackson/databind/ObjectMapper;->readValue\(',
        r'enableDefaultTyping\(',
        r'activateDefaultTyping\(',
        r'fromJson\(.*Object\.class',
    ],
    # ── SharedPreferences com dados sensíveis ────────────────────────────────
    "SharedPreferences (dados sensíveis em texto claro)": [
        r'getSharedPreferences\(',
        r'SharedPreferences;->getString\(',
        r'SharedPreferences;->putString\(',
        r'edit\(\).*putString\(',
        r'\.putString\(.*password',
        r'\.putString\(.*token',
        r'\.putString\(.*secret',
        r'\.putString\(.*key',
    ],
}

# ─── Tapjacking / Overlay ─────────────────────────────────────────────────────

TAPJACKING_PATTERNS = {
    # ── Overlay de sistema ───────────────────────────────────────────────────
    "TYPE_APPLICATION_OVERLAY (Overlay Attack)": [
        r'TYPE_APPLICATION_OVERLAY',
        r'TYPE_SYSTEM_ALERT',
        r'TYPE_SYSTEM_OVERLAY',
        r'TYPE_SYSTEM_ERROR',
        r'WindowManager\$LayoutParams;->TYPE_APPLICATION_OVERLAY',
        r'WindowManager\$LayoutParams;->TYPE_SYSTEM_ALERT',
        r'SYSTEM_ALERT_WINDOW',
    ],
    # ── Proteção ausente ─────────────────────────────────────────────────────
    "setFilterTouchesWhenObscured ausente": [
        r'setFilterTouchesWhenObscured\(.*false',
        r'filterTouchesWhenObscured.*false',
    ],
    # ── FLAG_SECURE ausente em activities sensíveis ──────────────────────────
    "FLAG_SECURE ausente (screenshot/overlay)": [
        r'\.method.*onCreate.*\(Landroid/os/Bundle;\)',
        r'getWindow\(\)\.setFlags\(',
        r'getWindow\(\)\.addFlags\(',
    ],
    # ── Accessibility Service (spyware vector) ───────────────────────────────
    "AccessibilityService (vetor de spyware)": [
        r'Landroid/accessibilityservice/AccessibilityService',
        r'Landroid/accessibilityservice/AccessibilityServiceInfo',
        r'onAccessibilityEvent\(',
        r'android\.permission\.BIND_ACCESSIBILITY_SERVICE',
    ],
}

_CURATED_JSON = Path(__file__).parent.parent / "tools" / "secret_locators" / "curated.json"


def _load_curated_locators() -> list[dict]:
    """Carrega locators do curated.json. Retorna lista de dicts com id, name, pattern compilado (bytes), secret_group."""
    if not _CURATED_JSON.exists():
        return []
    try:
        raw = json.loads(_CURATED_JSON.read_text(encoding="utf-8"))
    except Exception:
        return []

    locators = []
    seen_patterns = set()
    for entry in raw:
        pat_str = entry.get("pattern", "")
        if not pat_str or pat_str in seen_patterns:
            continue
        seen_patterns.add(pat_str)
        try:
            flags = re.IGNORECASE if "(?i)" in pat_str else 0
            compiled = re.compile(pat_str.encode(), flags)
            locators.append({
                "id":           entry.get("id", "unknown"),
                "name":         entry.get("name", entry.get("id", "unknown")),
                "pattern":      compiled,
                "secret_group": int(entry.get("secret_group", 0)),
                "confidence":   entry.get("confidence", "low"),
            })
        except Exception:
            continue
    return locators

# ─── Helpers ──────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _tool(name: str) -> str | None:
    """Retorna caminho do executável ou None."""
    found = shutil.which(name)
    if found:
        return found
    # Tenta na pasta tools/ do projeto
    tools_dir = Path(__file__).parent.parent / "tools"
    for ext in (".bat", ".cmd", ".exe", ""):
        candidate = tools_dir / (name + ext)
        if candidate.exists():
            return str(candidate)
    # Busca recursiva em subpastas (ex: tools/jadx/bin/jadx-gui.bat)
    for ext in (".bat", ".cmd", ".exe"):
        matches = list(tools_dir.rglob(name + ext))
        if matches:
            return str(matches[0])
    return None


def _run_tool(tool_path: str, args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """Executa um tool, usando shell=True + aspas se for .bat/.cmd (lida com espaços no path)."""
    if tool_path.lower().endswith((".bat", ".cmd")):
        quoted_args = " ".join(f'"{a}"' if " " in str(a) else str(a) for a in args)
        cmd = f'cmd /c "{tool_path}" {quoted_args}'
        kwargs.setdefault("shell", True)
        return subprocess.run(cmd, **kwargs)
    else:
        return subprocess.run([tool_path] + args, **kwargs)


def _popen_tool(tool_path: str, args: list[str], **kwargs) -> subprocess.Popen:
    """Popen de um tool, usando 'cmd /c' se for .bat/.cmd.
    Injeta JAVA_HOME e PATH com o java local no ambiente do processo filho."""
    from core.deps import _java_exe
    java = _java_exe()

    env = os.environ.copy()
    if java:
        env["JAVA_HOME"] = str(java.parent.parent)
        env["PATH"]      = str(java.parent) + os.pathsep + env.get("PATH", "")

    if tool_path.lower().endswith((".bat", ".cmd")):
        quoted_args = " ".join(f'"{a}"' if " " in str(a) else str(a) for a in args)
        cmd = f'cmd /c "{tool_path}" {quoted_args}'
        return subprocess.Popen(cmd, shell=True, env=env, **kwargs)
    else:
        cmd = [tool_path] + args
    return subprocess.Popen(cmd, env=env, **kwargs)



def _pkg_from_apk(apk_path: str) -> str:
    """Extrai package name do APK via aapt ou lendo o manifest."""
    aapt = _tool("aapt") or _tool("aapt2")
    if aapt:
        try:
            r = subprocess.run([aapt, "dump", "badging", apk_path],
                               capture_output=True, text=True, timeout=15)
            for line in r.stdout.splitlines():
                if line.startswith("package:"):
                    m = re.search(r"name='([^']+)'", line)
                    if m:
                        return m.group(1)
        except Exception:
            pass
    # Fallback: nome do arquivo
    return Path(apk_path).stem


def _results_dir(pkg: str, sub: str) -> Path:
    from core.report_paths import static_dir, dynamic_dir
    # sub "analysis" -> static (apk_analyzer faz analise estatica)
    return static_dir(pkg)


def _session_dir(pkg: str) -> Path:
    """Cria e retorna uma pasta de sessao unica para analise estatica."""
    from core.report_paths import static_dir
    return static_dir(pkg)


def _print_section(title: str):
    print(f"\n{_CYAN}{'─' * 70}{_RESET}")
    print(f"{_CYAN}{_BOLD}  {title}{_RESET}")
    print(f"{_CYAN}{'─' * 70}{_RESET}\n")


def _scan_files(folder: Path, patterns: dict[str, list[str]],
                extensions: tuple = (".smali", ".java", ".kt", ".xml")) -> dict:
    """
    Varre arquivos no folder buscando padrões regex.
    Retorna dict: {categoria: [{file, line, content}]}
    """
    results: dict[str, list[dict]] = {}
    compiled = {cat: [re.compile(p) for p in pats] for cat, pats in patterns.items()}

    files = [f for f in folder.rglob("*") if f.suffix in extensions and f.is_file()]
    total = len(files)

    for idx, fpath in enumerate(files):
        sys.stdout.write(f"\r  {_DIM}Analisando {idx+1}/{total} arquivos...{_RESET}  ")
        sys.stdout.flush()
        try:
            text = fpath.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        for lineno, line in enumerate(text.splitlines(), 1):
            for cat, regexes in compiled.items():
                for rx in regexes:
                    if rx.search(line):
                        results.setdefault(cat, []).append({
                            "file":    str(fpath.relative_to(folder)),
                            "line":    lineno,
                            "content": line.strip()[:120],
                        })
                        break  # uma match por categoria por linha

    print(f"\r  {_GREEN}✔ {total} arquivos analisados{_RESET}                    ")
    return results


def _print_results(results: dict, label: str):
    if not results:
        print(f"  {_DIM}Nenhuma ocorrência encontrada para {label}.{_RESET}")
        return
    total = sum(len(v) for v in results.values())
    print(f"  {_YELLOW}→ {total} ocorrência(s) encontrada(s){_RESET}\n")
    for cat, hits in results.items():
        print(f"  {_CYAN}{cat}{_RESET}  {_DIM}({len(hits)} hits){_RESET}")
        for h in hits[:8]:  # máx 8 por categoria no terminal
            print(f"    {_DIM}{h['file']}:{h['line']}{_RESET}")
            print(f"      {_WHITE}{h['content']}{_RESET}")
        if len(hits) > 8:
            print(f"    {_DIM}... +{len(hits)-8} mais (ver arquivo de resultados){_RESET}")
        print()


def _save_results(results: dict, out_file: Path):
    with open(out_file, "w", encoding="utf-8") as f:
        for cat, hits in results.items():
            f.write(f"\n=== {cat} ===\n")
            for h in hits:
                f.write(f"  {h['file']}:{h['line']}\n")
                f.write(f"    {h['content']}\n")
    print(f"  {_GREEN}✔ Resultados salvos em: {out_file}{_RESET}")


# ─── Download APK do dispositivo ─────────────────────────────────────────────

def pull_apk_from_device(adb: str, pkg: str) -> str | None:
    """
    Baixa todos os APKs do dispositivo (base + splits) para results/<pkg>/apk/.
    Retorna path do APK base (base.apk ou primeiro encontrado).
    """
    print(f"{_CYAN}→ Localizando APK de {pkg} no dispositivo...{_RESET}")
    r = subprocess.run([adb, "shell", "pm", "path", pkg],
                       capture_output=True, text=True, timeout=10)

    # pm path pode retornar múltiplas linhas para split APKs:
    # package:/data/app/.../base.apk
    # package:/data/app/.../split_config.arm64_v8a.apk
    remote_paths = re.findall(r"package:(.+\.apk)", r.stdout)
    if not remote_paths:
        print(f"{_RED}✖ Package não encontrado: {pkg}{_RESET}")
        return None

    out_dir = RESULTS_DIR / pkg / "apk"
    out_dir.mkdir(parents=True, exist_ok=True)

    base_local = None
    for remote_path in remote_paths:
        remote_path = remote_path.strip()
        remote_name = remote_path.split("/")[-1]
        local_name  = f"{pkg}.apk" if remote_name == "base.apk" else remote_name
        local_path  = out_dir / local_name

        print(f"  {_DIM}{remote_path}{_RESET}")
        r2 = subprocess.run([adb, "pull", remote_path, str(local_path)], capture_output=True)
        if r2.returncode != 0:
            # Fallback via su
            tmp = "/sdcard/_nd_apk_tmp.apk"
            subprocess.run([adb, "shell", "su", "-c", f"cp '{remote_path}' '{tmp}'"], capture_output=True)
            r3 = subprocess.run([adb, "pull", tmp, str(local_path)], capture_output=True)
            subprocess.run([adb, "shell", "rm", "-f", tmp], capture_output=True)
            if r3.returncode != 0:
                print(f"  {_RED}✖ Falha ao baixar {remote_name}{_RESET}")
                continue

        if base_local is None or remote_name == "base.apk":
            base_local = str(local_path)

    if base_local:
        total = len(list(out_dir.glob("*.apk")))
        if total > 1:
            print(f"{_GREEN}✔ {total} APK(s) salvos em: {out_dir}{_RESET}")
        else:
            print(f"{_GREEN}✔ APK salvo em: {base_local}{_RESET}")
        return base_local

    print(f"{_RED}✖ Falha ao baixar APK{_RESET}")
    return None



# ─── Decompilação ─────────────────────────────────────────────────────────────

def decompile_apktool(apk_path: str) -> Path | None:
    """Descompila APK com apktool. Retorna pasta de saída."""
    from core.deps import _java_exe, TOOLS_DIR as _TOOLS_DIR

    java = _java_exe()
    jar  = _TOOLS_DIR / "apktool.jar"

    if not jar.exists():
        print(f"{_RED}✖ apktool.jar não encontrado. Instale via menu Setup → Instalar Ferramentas.{_RESET}")
        return None
    if not java:
        print(f"{_RED}✖ Java não encontrado. Instale via menu Setup → Instalar Ferramentas.{_RESET}")
        return None

    pkg = _pkg_from_apk(apk_path)
    out = RESULTS_DIR / pkg / "decompiled" / "smali"
    # Reutiliza se já existe smali válido
    if out.exists() and any(out.rglob("*.smali")):
        print(f"{_GREEN}✔ Smali já existe em: {out}{_RESET}")
        return out
    out.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["PATH"]      = str(java.parent) + os.pathsep + env.get("PATH", "")
    env["JAVA_HOME"] = str(java.parent.parent)

    print(f"{_CYAN}→ Descompilando com apktool...{_RESET}")
    r = subprocess.run(
        [str(java), "-jar", str(jar), "d", apk_path, "-o", str(out), "-f"],
        capture_output=True, text=True, timeout=180, env=env
    )
    if out.exists() and any(out.rglob("*.smali")):
        print(f"{_GREEN}✔ Descompilado em: {out}{_RESET}")
        return out
    print(f"{_RED}✖ apktool falhou: {(r.stderr or r.stdout)[:300]}{_RESET}")
    return None


def decompile_jadx(apk_path: str):
    """Abre jadx-gui no APK (não bloqueante)."""
    tool = _tool("jadx-gui")
    if not tool:
        print(f"{_RED}✖ jadx não encontrado. Instale via menu Setup → Instalar Ferramentas.{_RESET}")
        return
    print(f"{_CYAN}→ Abrindo jadx-gui...{_RESET}")
    _popen_tool(tool, [apk_path])
    print(f"{_GREEN}✔ jadx-gui aberto{_RESET}")


def decompile_jadx_cli(apk_path: str, out_dir: Path) -> Path | None:
    """Descompila APK com jadx CLI para Java. Retorna pasta ou None."""
    from core.deps import _java_exe, TOOLS_DIR as _TOOLS_DIR
    java = _java_exe()
    if not java:
        print(f"  {_DIM}Java não encontrado — pulando jadx{_RESET}")
        return None

    jar = next((_TOOLS_DIR / "jadx" / "lib").rglob("jadx-*-all.jar"), None) \
       or next(_TOOLS_DIR.rglob("jadx-*-all.jar"), None)
    if not jar:
        print(f"  {_DIM}jadx jar não encontrado em tools/ — pulando{_RESET}")
        return None

    out = out_dir / "jadx"
    out.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["JAVA_HOME"] = str(java.parent.parent)
    env["PATH"]      = str(java.parent) + os.pathsep + env.get("PATH", "")

    print(f"  {_CYAN}→ jadx (Java)...{_RESET}", end=" ", flush=True)
    try:
        # --no-res evita abrir a GUI; --show-bad-code inclui classes com erros
        r = subprocess.run(
            [str(java), "-jar", str(jar),
             "--output-dir", str(out), "--no-res", "--show-bad-code", apk_path],
            capture_output=True, text=True, timeout=300, env=env
        )
    except Exception as e:
        print(f"{_RED}✖ erro: {e}{_RESET}")
        return None
    if out.exists() and any(out.rglob("*.java")):
        print(f"{_GREEN}✔{_RESET}")
        return out
    print(f"{_YELLOW}✖ sem output{_RESET}")


# ─── Análise de Certificate Pinning ──────────────────────────────────────────

def analyze_pinning(apk_path: str, folder: Path | None = None,
                    out_dir: Path | None = None) -> dict:
    _print_section("Certificate Pinning — Análise")
    if folder is None:
        folder = decompile_apktool(apk_path)
    if folder is None:
        return {}
    results = _scan_files(folder, PINNING_PATTERNS,
                          extensions=(".smali", ".java", ".kt", ".xml"))
    _print_results(results, "Certificate Pinning")
    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    out = out_dir / "cert_pinning.txt"
    _save_results(results, out)
    return results


# ─── Análise de Root Detection ────────────────────────────────────────────────

def analyze_root_detection(apk_path: str, folder: Path | None = None,
                           out_dir: Path | None = None) -> dict:
    _print_section("Root Detection — Análise")
    if folder is None:
        folder = decompile_apktool(apk_path)
    if folder is None:
        return {}
    results = _scan_files(folder, ROOT_PATTERNS,
                          extensions=(".smali", ".java", ".kt", ".xml"))
    _print_results(results, "Root Detection")
    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    out = out_dir / "root_detection.txt"
    _save_results(results, out)
    return results


# ─── Análise completa (pinning + root) ───────────────────────────────────────

def analyze_apk_full(apk_path: str):
    """
    Analise completa de APK usando apktool (smali) como base.
    """
    _print_section("Análise Completa de APK")
    print(f"  {_WHITE}APK: {apk_path}{_RESET}\n")

    # ── apktool (base) ────────────────────────────────────────────────────────
    smali_folder = decompile_apktool(apk_path)
    if not smali_folder:
        input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        return

    # ── Análises estáticas (smali) ────────────────────────────────────────────
    pkg     = _pkg_from_apk(apk_path)
    session = _session_dir(pkg)
    print(f"\n  {_DIM}Sessão: {session}{_RESET}")

    analyze_pinning(apk_path, smali_folder, out_dir=session)
    analyze_root_detection(apk_path, smali_folder, out_dir=session)
    analyze_antidebug(apk_path, smali_folder, out_dir=session)
    analyze_crypto_misuse(apk_path, smali_folder, out_dir=session)
    analyze_webview(apk_path, smali_folder, out_dir=session)
    analyze_insecure_ipc(apk_path, smali_folder, out_dir=session)
    analyze_dynamic_code(apk_path, smali_folder, out_dir=session)
    analyze_injection(apk_path, smali_folder, out_dir=session)
    analyze_serialization(apk_path, smali_folder, out_dir=session)
    analyze_tapjacking(apk_path, smali_folder, out_dir=session)
    analyze_hardcode(apk_path, smali_folder, out_dir=session)

    print(f"\n  {_GREEN}✔ Todos os resultados em: {session}{_RESET}")
    input(f"\n{_DIM}→ Enter para continuar...{_RESET}")


# ─── Análise Anti-Debug / Anti-Tamper ────────────────────────────────────────

def analyze_antidebug(apk_path: str, folder: Path | None = None,
                      out_dir: Path | None = None) -> dict:
    _print_section("Anti-Debug / Anti-Tamper — Análise")
    if folder is None:
        folder = decompile_apktool(apk_path)
    if folder is None:
        return {}
    results = _scan_files(folder, ANTIDEBUG_PATTERNS,
                          extensions=(".smali", ".java", ".kt", ".xml"))
    _print_results(results, "Anti-Debug / Anti-Tamper")
    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    out = out_dir / "antidebug.txt"
    _save_results(results, out)
    return results


# ─── Análise de Hardcode (arquitetura apkprobe) ───────────────────────────────

def _scan_file_for_secrets(args: tuple) -> tuple[str, list[dict]]:
    """Worker: varre um arquivo em modo bytes buscando todos os locators."""
    fpath, locators, base_folder = args
    hits = []
    seen_secrets: set[bytes] = set()
    try:
        with open(fpath, "rb") as f:
            for lineno, line in enumerate(f, 1):
                for loc in locators:
                    m = loc["pattern"].search(line)
                    if not m:
                        continue
                    try:
                        secret = m.group(loc["secret_group"])
                    except IndexError:
                        secret = m.group(0)
                    if secret in seen_secrets:
                        continue
                    seen_secrets.add(secret)
                    try:
                        secret_str = secret.decode("utf-8", errors="replace").strip()
                        line_str   = line.decode("utf-8", errors="replace").strip()[:120]
                    except Exception:
                        continue
                    hits.append({
                        "locator_name": loc["name"],
                        "confidence":   loc["confidence"],
                        "file":         str(Path(fpath).relative_to(base_folder)),
                        "line":         lineno,
                        "secret":       secret_str,
                        "content":      line_str,
                    })
    except Exception:
        pass
    return str(fpath), hits


def analyze_hardcode(apk_path: str, folders: Path | list[Path] | None = None,
                     out_dir: Path | None = None) -> dict:
    """
    Scan de dados sensíveis hardcoded usando padrões do curated.json (arquitetura apkprobe).
    - Aceita uma pasta ou lista de pastas (multi-decompilador)
    - Lê arquivos em modo bytes (evita erros de encoding)
    - Captura apenas o grupo secreto (secret_group) de cada match
    - Deduplica por valor do segredo globalmente
    - Paraleliza com ThreadPoolExecutor
    """
    _print_section("Dados Sensíveis Hardcoded — Análise")

    # Normaliza para lista de pastas
    if folders is None:
        folder = decompile_apktool(apk_path)
        if folder is None:
            return {}
        folder_list = [folder]
    elif isinstance(folders, Path):
        folder_list = [folders]
    else:
        folder_list = [f for f in folders if f is not None]

    if not folder_list:
        return {}

    locators = _load_curated_locators()
    if not locators:
        print(f"  {_YELLOW}⚠ curated.json não encontrado — usando padrões internos{_RESET}")
        results = _scan_files(folder_list[0], HARDCODE_PATTERNS,
                              extensions=(".smali", ".java", ".kt", ".xml",
                                          ".properties", ".json", ".yaml", ".yml",
                                          ".gradle", ".txt"))
        _print_results(results, "Dados Sensíveis Hardcoded")
        pkg = _pkg_from_apk(apk_path)
        if out_dir is None:
            out_dir = _results_dir(pkg, "analysis")
        _save_results(results, out_dir / "hardcode.txt")
        return results

    extensions = (".smali", ".java", ".kt", ".xml", ".properties",
                  ".json", ".yaml", ".yml", ".gradle", ".txt")

    # Coleta todos os arquivos de todas as pastas
    all_files: list[tuple[Path, Path]] = []  # (arquivo, base_folder)
    for base in folder_list:
        for f in base.rglob("*"):
            if f.suffix in extensions and f.is_file():
                all_files.append((f, base))

    total = len(all_files)
    decompiler_labels = ", ".join(b.name for b in folder_list)
    print(f"  {_DIM}Carregados {len(locators)} locators | {total} arquivos [{decompiler_labels}]{_RESET}")

    # Deduplicação global de segredos
    global_seen: set[bytes] = set()
    grouped: dict[str, list[dict]] = {}
    done = 0

    args_list = [(str(f), locators, base) for f, base in all_files]

    with ThreadPoolExecutor(max_workers=8) as executor:
        futures = {executor.submit(_scan_file_for_secrets, a): a for a in args_list}
        for fut in as_completed(futures):
            done += 1
            sys.stdout.write(f"\r  {_DIM}Escaneando {done}/{total} arquivos...{_RESET}  ")
            sys.stdout.flush()
            _, hits = fut.result()
            for h in hits:
                secret_bytes = h["secret"].encode()
                if secret_bytes in global_seen:
                    continue
                global_seen.add(secret_bytes)
                grouped.setdefault(h["locator_name"], []).append(h)

    print(f"\r  {_GREEN}✔ {total} arquivos analisados{_RESET}                    ")

    if not grouped:
        print(f"  {_DIM}Nenhuma ocorrência encontrada.{_RESET}")
    else:
        total_hits = sum(len(v) for v in grouped.values())
        print(f"  {_YELLOW}→ {total_hits} ocorrência(s) únicas em {len(grouped)} categoria(s){_RESET}\n")
        for name, hits in sorted(grouped.items(), key=lambda x: -len(x[1])):
            conf = hits[0].get("confidence", "?")
            conf_color = _GREEN if conf == "high" else (_YELLOW if conf == "medium" else _DIM)
            print(f"  {_CYAN}{name}{_RESET}  {conf_color}[{conf}]{_RESET}  {_DIM}({len(hits)} hits){_RESET}")
            for h in hits[:5]:
                print(f"    {_DIM}{h['file']}:{h['line']}{_RESET}")
                print(f"      {_WHITE}{h['secret'][:100]}{_RESET}")
            if len(hits) > 5:
                print(f"    {_DIM}... +{len(hits)-5} mais (ver arquivo de resultados){_RESET}")
            print()

    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    out = out_dir / "hardcode.txt"
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"Decompiladores usados: {decompiler_labels}\n")
        for name, hits in sorted(grouped.items(), key=lambda x: -len(x[1])):
            f.write(f"\n=== {name} ===\n")
            for h in hits:
                f.write(f"  [{h.get('confidence','?')}] {h['file']}:{h['line']}\n")
                f.write(f"    secret: {h['secret']}\n")
                f.write(f"    linha:  {h['content']}\n")
    print(f"  {_GREEN}✔ Resultados salvos em: {out}{_RESET}")

    return {name: [{"file": h["file"], "line": h["line"], "content": h["content"]} for h in hits]
            for name, hits in grouped.items()}


# ─── Análise de Crypto Misuse ─────────────────────────────────────────────────

def analyze_crypto_misuse(apk_path: str, folder: Path | None = None,
                          out_dir: Path | None = None) -> dict:
    _print_section("Crypto Misuse — Algoritmos Fracos / IV Hardcoded")
    if folder is None:
        folder = decompile_apktool(apk_path)
    if folder is None:
        return {}
    results = _scan_files(folder, CRYPTO_MISUSE_PATTERNS,
                          extensions=(".smali", ".java", ".kt", ".xml"))
    _print_results(results, "Crypto Misuse")
    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    _save_results(results, out_dir / "crypto_misuse.txt")
    return results


# ─── Análise de WebView / JavaScript Interface ────────────────────────────────

def analyze_webview(apk_path: str, folder: Path | None = None,
                    out_dir: Path | None = None) -> dict:
    _print_section("WebView / JavaScript Interface — Análise")
    if folder is None:
        folder = decompile_apktool(apk_path)
    if folder is None:
        return {}
    results = _scan_files(folder, WEBVIEW_PATTERNS,
                          extensions=(".smali", ".java", ".kt", ".xml"))
    _print_results(results, "WebView / JavaScript Interface")
    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    _save_results(results, out_dir / "webview.txt")
    return results


# ─── Análise de IPC Inseguro ──────────────────────────────────────────────────

def analyze_insecure_ipc(apk_path: str, folder: Path | None = None,
                         out_dir: Path | None = None) -> dict:
    _print_section("IPC Inseguro — PendingIntent / Broadcast / Clipboard")
    if folder is None:
        folder = decompile_apktool(apk_path)
    if folder is None:
        return {}
    results = _scan_files(folder, INSECURE_IPC_PATTERNS,
                          extensions=(".smali", ".java", ".kt", ".xml"))
    _print_results(results, "IPC Inseguro")
    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    _save_results(results, out_dir / "insecure_ipc.txt")
    return results


# ─── Análise de Dynamic Code Loading / Reflection ────────────────────────────

def analyze_dynamic_code(apk_path: str, folder: Path | None = None,
                         out_dir: Path | None = None) -> dict:
    _print_section("Dynamic Code Loading / Reflection — Análise")
    if folder is None:
        folder = decompile_apktool(apk_path)
    if folder is None:
        return {}
    results = _scan_files(folder, DYNAMIC_CODE_PATTERNS,
                          extensions=(".smali", ".java", ".kt", ".xml"))
    _print_results(results, "Dynamic Code Loading / Reflection")
    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    _save_results(results, out_dir / "dynamic_code.txt")
    return results


# ─── Análise de Injection (Command / SQL / Path / XXE) ───────────────────────

def analyze_injection(apk_path: str, folder: Path | None = None,
                      out_dir: Path | None = None) -> dict:
    _print_section("Injection — Command / SQL / Path Traversal / XXE")
    if folder is None:
        folder = decompile_apktool(apk_path)
    if folder is None:
        return {}
    results = _scan_files(folder, INJECTION_PATTERNS,
                          extensions=(".smali", ".java", ".kt", ".xml"))
    _print_results(results, "Injection")
    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    _save_results(results, out_dir / "injection.txt")
    return results


# ─── Análise de Serialização Insegura ────────────────────────────────────────

def analyze_serialization(apk_path: str, folder: Path | None = None,
                          out_dir: Path | None = None) -> dict:
    _print_section("Serialização Insegura — ObjectInputStream / Gson / SharedPrefs")
    if folder is None:
        folder = decompile_apktool(apk_path)
    if folder is None:
        return {}
    results = _scan_files(folder, SERIALIZATION_PATTERNS,
                          extensions=(".smali", ".java", ".kt", ".xml"))
    _print_results(results, "Serialização Insegura")
    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    _save_results(results, out_dir / "serialization.txt")
    return results


# ─── Análise de Tapjacking / Overlay ─────────────────────────────────────────

def analyze_tapjacking(apk_path: str, folder: Path | None = None,
                       out_dir: Path | None = None) -> dict:
    _print_section("Tapjacking / Overlay — TYPE_APPLICATION_OVERLAY / AccessibilityService")
    if folder is None:
        folder = decompile_apktool(apk_path)
    if folder is None:
        return {}
    results = _scan_files(folder, TAPJACKING_PATTERNS,
                          extensions=(".smali", ".java", ".kt", ".xml"))
    _print_results(results, "Tapjacking / Overlay")
    pkg = _pkg_from_apk(apk_path)
    if out_dir is None:
        out_dir = _results_dir(pkg, "analysis")
    _save_results(results, out_dir / "tapjacking.txt")
    return results


# ─── Custom URLs do AndroidManifest ──────────────────────────────────────────

def extract_custom_urls(manifest_path: str) -> list[str]:
    """Extrai deep links / custom URL schemes do AndroidManifest.xml."""
    urls = []
    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        for intent in root.findall(".//intent-filter"):
            has_view = intent.find(
                "./action[@android:name='android.intent.action.VIEW']", ns) is not None
            has_browsable = intent.find(
                "./category[@android:name='android.intent.category.BROWSABLE']", ns) is not None
            if has_view and has_browsable:
                for data in intent.findall("data", ns):
                    scheme = data.get(f"{{{ns['android']}}}scheme", "")
                    host   = data.get(f"{{{ns['android']}}}host", "")
                    path   = (data.get(f"{{{ns['android']}}}path", "") or
                              data.get(f"{{{ns['android']}}}pathPrefix", "") or
                              data.get(f"{{{ns['android']}}}pathPattern", ""))
                    if scheme:
                        urls.append(f"{scheme}://{host}{path}")
    except Exception as e:
        print(f"{_RED}✖ Erro ao parsear manifest: {e}{_RESET}")
    return urls


def analyze_custom_urls(apk_path: str | None = None,
                        manifest_path: str | None = None,
                        adb: str | None = None,
                        pkg: str | None = None):
    """
    Extrai custom URLs de:
    - manifest_path direto
    - apk_path (descompila primeiro)
    - pkg no dispositivo (baixa APK, descompila)
    """
    _print_section("Custom URL Schemes — AndroidManifest.xml")

    if manifest_path is None:
        # Precisa descompilar
        if apk_path is None and adb and pkg:
            apk_path = pull_apk_from_device(adb, pkg)
        if apk_path is None:
            print(f"{_RED}✖ Nenhuma fonte de APK fornecida.{_RESET}")
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
            return
        folder = decompile_apktool(apk_path)
        if folder is None:
            input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
            return
        manifest_path = str(folder / "AndroidManifest.xml")

    if not Path(manifest_path).exists():
        print(f"{_RED}✖ AndroidManifest.xml não encontrado em: {manifest_path}{_RESET}")
        input(f"\n{_DIM}→ Enter para continuar...{_RESET}")
        return

    urls = extract_custom_urls(manifest_path)
    if urls:
        print(f"  {_YELLOW}→ {len(urls)} URL scheme(s) encontrado(s):{_RESET}\n")
        for u in urls:
            print(f"  {_CYAN}  {u}{_RESET}")
        # Salva
        pkg_name = pkg or Path(apk_path or manifest_path).stem
        out = _results_dir(pkg_name, "analysis") / "custom_urls.txt"
        out.write_text("\n".join(urls), encoding="utf-8")
        print(f"\n  {_GREEN}✔ Salvo em: {out}{_RESET}")
    else:
        print(f"  {_DIM}Nenhum custom URL scheme encontrado.{_RESET}")

    input(f"\n{_DIM}→ Enter para continuar...{_RESET}")



# ─── APKLeaks ─────────────────────────────────────────────────────────────────

def run_apkleaks(apk_path: str):
    """
    Executa apkleaks no APK e exibe o output formatado.
    Salva resultado em results/<pkg>/analysis/<ts>/apkleaks.txt
    """
    _print_section("APKLeaks — URIs, Endpoints & Secrets")

    # Verifica se apkleaks está disponível
    tool = shutil.which("apkleaks") or shutil.which("apkleaks.exe")
    if not tool:
        print(f"  {_RED}✖ apkleaks não encontrado. Execute Setup → Verificar Dependências.{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    if not Path(apk_path).exists():
        print(f"  {_RED}✖ APK não encontrado: {apk_path}{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    pkg = _pkg_from_apk(apk_path)
    session = _session_dir(pkg)
    out_file = session / "apkleaks.txt"

    print(f"  {_DIM}APK: {apk_path}{_RESET}")
    print(f"  {_DIM}Saída: {out_file}{_RESET}\n")
    print(f"  {_CYAN}→ Executando apkleaks...{_RESET}\n")

    try:
        r = subprocess.run(
            [tool, "-f", apk_path, "-o", str(out_file)],
            text=True, timeout=300
        )
    except Exception as e:
        print(f"  {_RED}✖ Erro: {e}{_RESET}")
        input(f"\n  → Enter para continuar...")
        return

    # Exibe o conteúdo salvo com colorização por categoria
    if out_file.exists():
        print(f"\n{_DIM}{'─' * 70}{_RESET}")
        content = out_file.read_text(encoding="utf-8", errors="replace")
        for line in content.splitlines():
            if line.startswith("[") and line.endswith("]"):
                print(f"\n  {_CYAN}{_BOLD}{line}{_RESET}")
            elif line.startswith("- "):
                print(f"  {_WHITE}{line}{_RESET}")
            elif line.strip():
                print(f"  {_DIM}{line}{_RESET}")
        print(f"\n{_DIM}{'─' * 70}{_RESET}")
        print(f"  {_GREEN}✔ Resultado salvo em: {out_file}{_RESET}")
    else:
        print(f"  {_YELLOW}⚠ Nenhum arquivo de saída gerado.{_RESET}")

    input(f"\n  → Enter para continuar...")

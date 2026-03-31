/***
 * NoxDroid v5 — Android 9 · API 28 · NoxPlayer Pixel 2
 * by Mr_ofcodyx
 *
 * Fix crítico v5:
 *   SSLContext.init hook REMOVIDO — interferia com Zygisk
 *   que desmonta os cacerts via umount2(MNT_DETACH) no
 *   namespace do processo antes do app iniciar.
 *   O hook bloqueava a reinicialização limpa do Conscrypt.
 *
 * Estratégia SSL v5:
 *   TrustAll via SSLContext.getInstance + getDefault
 *   + hooks diretos Conscrypt/TrustManagerImpl
 *   + HttpsURLConnection defaults
 *   (sem tocar no SSLContext.init)
 */
"use strict";

// ═══════════════════════════════════════════════════════════════════
//  CONFIG
// ═══════════════════════════════════════════════════════════════════
var CONFIG = {
    ROOT_BYPASS:        true,
    NATIVE_BYPASS:      true,
    ADB_BYPASS:         true,
    EMULATOR_BYPASS:    true,
    KEYSTORE_BYPASS:    true,
    SSL_PINNING_BYPASS: true,
    HTTP_INTERCEPT:     true,
    SCREEN_BYPASS:      true,
    MAX_BODY_LOG:       4096,
    HTTP_STACK:         false,
    HILT_PATCH_DELAY:   4000,
    HV_PATCH_DELAY:     4000,
};

// ═══════════════════════════════════════════════════════════════════
//  OUTPUT SYSTEM
// ═══════════════════════════════════════════════════════════════════
var C = {
    rst:"\x1b[0m", r:"\x1b[31m", g:"\x1b[32m", y:"\x1b[33m", b:"\x1b[34m",
    m:"\x1b[35m", c:"\x1b[36m", w:"\x1b[37m", gr:"\x1b[90m",
    bold:"\x1b[1m", dim:"\x1b[2m",
    br:"\x1b[91m", bg:"\x1b[92m", by:"\x1b[93m", bc:"\x1b[96m", bw:"\x1b[97m",
};

var TAG = {
    ROOT:   C.br   + " ROOT "   + C.rst,
    ADB:    C.y    + " ADB  "   + C.rst,
    EMU:    C.by   + " EMU  "   + C.rst,
    SSL:    C.bc   + " SSL  "   + C.rst,
    KS:     C.c    + " KS   "   + C.rst,
    HTTP:   C.bg   + " HTTP "   + C.rst,
    SCREEN: C.gr   + "SCREEN"   + C.rst,
    NAT:    C.m    + " NAT  "   + C.rst,
};

var I = {
    ok:   C.bg + "✔" + C.rst,
    skip: C.gr + "·" + C.rst,
    warn: C.by + "!" + C.rst,
    err:  C.br + "✘" + C.rst,
    dbg:  C.bc + "→" + C.rst,
    lock: C.c  + "⌁" + C.rst,
    net:  C.b  + "⇄" + C.rst,
};

var STATS = {
    ROOT:  { ok: 0, skip: 0 }, ADB:   { ok: 0, skip: 0 },
    EMU:   { ok: 0, skip: 0 }, SSL:   { ok: 0, skip: 0 },
    KS:    { ok: 0, skip: 0 }, HTTP:  { ok: 0, skip: 0 },
    SCREEN:{ ok: 0, skip: 0 }, NAT:   { ok: 0, skip: 0 },
};

function ok(mod, msg)           { STATS[mod].ok++;   console.log(" " + TAG[mod] + "  " + I.ok   + "  " + C.bw + msg + C.rst); }
function skip(mod, msg, reason) { STATS[mod].skip++; console.log(" " + TAG[mod] + "  " + I.skip + "  " + C.gr + msg + (reason ? C.dim + "  (" + reason.split("\n")[0].substring(0,80) + ")" : "") + C.rst); }
function info(mod, msg)         { console.log(" " + TAG[mod] + "  " + I.dbg + "  " + C.c + msg + C.rst); }

function sh(mod, label, fn) {
    try { fn(); }
    catch (e) { skip(mod, label, e.message ? e.message.split("\n")[0].substring(0,80) : String(e)); }
}

function section(title, icon) {
    var line = "─".repeat(Math.max(0, 52 - title.length));
    console.log("\n " + C.bold + C.gr + "┄┄┄" + C.rst + " " + C.bold + C.bw + (icon || "◆") + " " + title + C.rst + " " + C.gr + line + C.rst);
}

var _tid = 0;
function daemon(label, fn) {
    _tid++;
    var uid = "D" + _tid;
    sh("SSL", "thread:" + label, function () {
        var R = Java.use("java.lang.Runnable");
        var W = Java.registerClass({
            name: "noxdroid.v5." + uid,
            implements: [R],
            methods: { run: function () { Java.perform(fn); } }
        });
        var t = Java.use("java.lang.Thread").$new(W.$new());
        t.setName("NoxDroid-" + label);
        t.setDaemon(true);
        t.start();
        info("SSL", "thread " + label + " iniciado");
    });
}

// ═══════════════════════════════════════════════════════════════════
//  BANNER + SUMMARY
// ═══════════════════════════════════════════════════════════════════
function banner() {
    console.log("");
    console.log(" " + C.gr + "╭────────────────────────────────────────────────────────╮" + C.rst);
    console.log(" " + C.gr + "│" + C.rst + "  " + C.bold + C.bc + "NoxDroid" + C.rst + " " + C.bw + "v5" + C.rst + C.gr + "  ·  " + C.rst + C.y + "Android 9" + C.rst + C.gr + "  ·  " + C.rst + C.w + "API 28" + C.rst + C.gr + "  ·  " + C.rst + C.m + "Pixel 2" + C.rst + "                  " + C.gr + "│" + C.rst);
    console.log(" " + C.gr + "│" + C.rst + "  " + C.gr + "NAT  ROOT  ADB  EMU  KS  SSL  HTTP  SCREEN" + C.rst + "              " + C.gr + "│" + C.rst);
    console.log(" " + C.gr + "╰────────────────────────────────────────────────────────╯" + C.rst);
    console.log("");
}

function summary(elapsed) {
    console.log("");
    console.log(" " + C.gr + "╭─ resumo " + "─".repeat(49) + "╮" + C.rst);
    ["NAT","ROOT","ADB","EMU","KS","SSL","HTTP","SCREEN"].forEach(function(m) {
        var s = STATS[m];
        console.log(" " + C.gr + "│" + C.rst + "  " + TAG[m] + "  " + C.bg + "✔ " + s.ok + C.rst + "  " + C.gr + "· " + s.skip + C.rst);
    });
    console.log(" " + C.gr + "│" + C.rst);
    console.log(" " + C.gr + "│" + C.rst + "  " + I.ok + "  " + C.bg + C.bold + "pronto" + C.rst + C.gr + "  ·  Hilt patch em +" + CONFIG.HILT_PATCH_DELAY + "ms  ·  " + elapsed + "ms init" + C.rst);
    console.log(" " + C.gr + "╰" + "─".repeat(57) + "╯" + C.rst);
    console.log("");
}

// ═══════════════════════════════════════════════════════════════════
//  0. NATIVE — libc open/access/stat
// ═══════════════════════════════════════════════════════════════════
function hookNative() {
    section("Native bypass", "⬡");
    var BLOCKED = ["/dev/ksu","/data/adb/ksu","/data/adb/ksud","/data/adb/magisk","/sbin/.magisk","/dev/socket/su"];

    function patchLibc(sym, argIdx) {
        sh("NAT", "libc." + sym, function () {
            var ptr = Module.findExportByName("libc.so", sym);
            if (!ptr) throw new Error("export ausente");
            Interceptor.attach(ptr, { onEnter: function (args) {
                try {
                    var p = args[argIdx].readUtf8String();
                    if (!p) return;
                    for (var i = 0; i < BLOCKED.length; i++) {
                        if (p.indexOf(BLOCKED[i]) !== -1) { ok("NAT", sym + "() bloqueado: " + p); args[argIdx] = Memory.allocUtf8String("/dev/null"); return; }
                    }
                    if (p.indexOf("/ksu") !== -1 || p.indexOf("kernelsu") !== -1) { ok("NAT", sym + "() KSU: " + p); args[argIdx] = Memory.allocUtf8String("/dev/null"); }
                } catch(e) {}
            }});
            ok("NAT", "libc." + sym + " hook instalado");
        });
    }
    patchLibc("open", 0);
    patchLibc("access", 0);
    sh("NAT", "libc.__xstat", function () {
        var ptr = Module.findExportByName("libc.so", "__xstat") || Module.findExportByName("libc.so", "stat");
        if (!ptr) throw new Error("export ausente");
        Interceptor.attach(ptr, { onEnter: function (args) {
            try {
                var p = args[1].readUtf8String();
                if (!p) return;
                for (var i = 0; i < BLOCKED.length; i++) if (p.indexOf(BLOCKED[i]) !== -1) { ok("NAT","stat() bloqueado: "+p); args[1] = Memory.allocUtf8String("/dev/null"); }
            } catch(e) {}
        }});
        ok("NAT", "libc.stat hook instalado");
    });
}

// ═══════════════════════════════════════════════════════════════════
//  1. ROOT BYPASS
// ═══════════════════════════════════════════════════════════════════
function hookRoot() {
    section("Root bypass", "⬡");
    var ROOT_PATHS = ["/system/app/Superuser.apk","/system/xbin/su","/system/bin/su","/sbin/su","/data/local/xbin/su","/data/local/bin/su","/data/local/su","/system/sd/xbin/su","/system/bin/failsafe/su","/system/app/SuperSU","/system/app/Magisk","/sbin/.magisk","/data/adb/magisk","/cache/.disable_selinux","/data/adb/ksu","/data/adb/ksud","/dev/ksu"];
    var ROOT_CMDS  = ["su","which su","id","busybox","mount","ksud","ksu"];

    sh("ROOT","RootBeer",function(){
        var RB=Java.use("com.scottyab.rootbeer.RootBeer"); var count=0;
        ["isRooted","isRootedWithoutBusyBoxCheck","detectRootManagementApps","detectPotentiallyDangerousApps","checkForBusyBoxBinary","checkForSuBinary","checkSuExists","checkForRWPaths","checkForDangerousProps","checkForRootNative","detectTestKeys"].forEach(function(m){try{RB[m].implementation=function(){return false;};count++;}catch(e){}});
        ok("ROOT","RootBeer → false  ("+count+" métodos)");
    });
    sh("ROOT","Runtime.exec",function(){
        var RT=Java.use("java.lang.Runtime");
        function blockCmd(cmd){if(!cmd)return false;for(var i=0;i<ROOT_CMDS.length;i++)if(cmd.indexOf(ROOT_CMDS[i])!==-1)return true;return false;}
        RT.exec.overload("java.lang.String").implementation=function(cmd){if(blockCmd(cmd)){ok("ROOT","exec blocked: "+cmd);throw Java.use("java.io.IOException").$new("blocked");}return this.exec(cmd);};
        RT.exec.overload("[Ljava.lang.String;").implementation=function(cmds){var a=Java.array("java.lang.String",cmds);if(a.length>0&&blockCmd(a[0])){ok("ROOT","exec[] blocked: "+a[0]);throw Java.use("java.io.IOException").$new("blocked");}return this.exec(cmds);};
        RT.exec.overload("[Ljava.lang.String;","[Ljava.lang.String;","java.io.File").implementation=function(cmds,env,dir){var a=Java.array("java.lang.String",cmds);if(a.length>0&&blockCmd(a[0])){ok("ROOT","exec(env) blocked: "+a[0]);throw Java.use("java.io.IOException").$new("blocked");}return this.exec(cmds,env,dir);};
        ok("ROOT","Runtime.exec  (3 overloads)");
    });
    sh("ROOT","File.exists",function(){
        Java.use("java.io.File").exists.implementation=function(){
            var p=this.getAbsolutePath();
            for(var i=0;i<ROOT_PATHS.length;i++)if(p===ROOT_PATHS[i]){ok("ROOT","File.exists blocked: "+p);return false;}
            if(p.indexOf("magisk")!==-1||p.indexOf(".supersu")!==-1||p.indexOf("kernelsu")!==-1||p.indexOf("/ksu")!==-1){ok("ROOT","File.exists pattern: "+p);return false;}
            return this.exists();
        };
        ok("ROOT","File.exists  (paths + patterns)");
    });
    sh("ROOT","FileInputStream /proc",function(){
        Java.use("java.io.FileInputStream").$init.overload("java.lang.String").implementation=function(p){
            if(p&&(p.indexOf("/proc/self/status")!==-1||p.indexOf("/proc/self/attr")!==-1||p.indexOf("/proc/net/unix")!==-1)){ok("ROOT","FileInputStream blocked: "+p);return this.$init("/dev/null");}
            return this.$init(p);
        };
        ok("ROOT","FileInputStream /proc redirect");
    });
    sh("ROOT","Build.TAGS",function(){Object.defineProperty(Java.use("android.os.Build"),"TAGS",{get:function(){return "release-keys";}});ok("ROOT","Build.TAGS → release-keys");});
    sh("ROOT","PackageManager",function(){
        var RPKGS=["com.noshufou.android.su","eu.chainfire.supersu","com.koushikdutta.superuser","com.thirdparty.superuser","com.topjohnwu.magisk","me.weishu.kernelsu","com.kingroot.kinguser","com.kingo.root"];
        Java.use("android.content.pm.PackageManager").getPackageInfo.overload("java.lang.String","int").implementation=function(pkg,f){for(var i=0;i<RPKGS.length;i++)if(pkg===RPKGS[i]){ok("ROOT","PackageManager blocked: "+pkg);throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new(pkg);}return this.getPackageInfo(pkg,f);};
        ok("ROOT","PackageManager  ("+RPKGS.length+" pacotes)");
    });
    sh("ROOT","SystemProperties",function(){
        var SP=Java.use("android.os.SystemProperties");
        function fp(k){if(k==="ro.debuggable")return "0";if(k==="ro.secure")return "1";if(k==="ro.build.tags")return "release-keys";return null;}
        SP.get.overload("java.lang.String").implementation=function(k){return fp(k)||this.get(k);};
        SP.get.overload("java.lang.String","java.lang.String").implementation=function(k,d){return fp(k)||this.get(k,d);};
        ok("ROOT","SystemProperties  (ro.debuggable · ro.secure · ro.build.tags)");
    });
}

// ═══════════════════════════════════════════════════════════════════
//  2. ADB BYPASS
// ═══════════════════════════════════════════════════════════════════
function hookAdb() {
    section("ADB bypass", "⬡");
    sh("ADB","Debug.isDebuggerConnected",function(){
        var D=Java.use("android.os.Debug");
        D.isDebuggerConnected.implementation=function(){return false;};
        D.waitingForDebugger.implementation=function(){return false;};
        ok("ADB","isDebuggerConnected / waitingForDebugger → false");
    });
    sh("ADB","FLAG_DEBUGGABLE",function(){
        Java.use("android.content.ContextWrapper").getApplicationInfo.implementation=function(){var ai=this.getApplicationInfo();try{ai.flags.value=ai.flags.value&~2;}catch(e){}return ai;};
        ok("ADB","ApplicationInfo.FLAG_DEBUGGABLE removido");
    });
    sh("ADB","Settings.Global",function(){
        Java.use("android.provider.Settings$Global").getInt.overload("android.content.ContentResolver","java.lang.String","int").implementation=function(cr,name,def){
            if(name==="adb_enabled"||name==="development_settings_enabled"){ok("ADB","Settings.Global."+name+" → 0");return 0;}
            return this.getInt(cr,name,def);
        };
        ok("ADB","Settings.Global  (adb_enabled · development)");
    });
    var _strictDone=false;
    sh("ADB","StrictMode",function(){
        Java.use("android.os.StrictMode").setThreadPolicy.implementation=function(){if(!_strictDone){ok("ADB","StrictMode neutralizado");_strictDone=true;}};
        ok("ADB","StrictMode.setThreadPolicy neutralizado");
    });
}

// ═══════════════════════════════════════════════════════════════════
//  3. EMULATOR BYPASS
// ═══════════════════════════════════════════════════════════════════
function hookEmulator() {
    section("Emulator bypass", "⬡");
    sh("EMU","Build props (Pixel 2 / API 28)",function(){
        var B=Java.use("android.os.Build");
        var fake={FINGERPRINT:"google/walleye/walleye:9/PQ3A.190705.003/5736940:user/release-keys",MODEL:"Pixel 2",MANUFACTURER:"Google",BRAND:"google",DEVICE:"walleye",PRODUCT:"walleye",HARDWARE:"walleye",BOARD:"walleye"};
        var count=0;
        Object.keys(fake).forEach(function(k){try{var v=fake[k];Object.defineProperty(B,k,{get:function(){return v;}});count++;}catch(e){}});
        ok("EMU","Build props spoofados  ("+count+" campos · Pixel 2 walleye)");
    });
    sh("EMU","Build.VERSION.SDK_INT",function(){Object.defineProperty(Java.use("android.os.Build$VERSION"),"SDK_INT",{get:function(){return 28;}});ok("EMU","SDK_INT → 28");});
    sh("EMU","TelephonyManager",function(){
        var TM=Java.use("android.telephony.TelephonyManager"); var count=0;
        [["getDeviceId",function(){return "358239051448958";}],["getNetworkOperatorName",function(){return "Vivo";}],["getSimOperatorName",function(){return "Vivo";}],["getPhoneType",function(){return 1;}],["getNetworkType",function(){return 13;}],["getSimCountryIso",function(){return "br";}],["getNetworkCountryIso",function(){return "br";}]].forEach(function(p){try{TM[p[0]].overload().implementation=p[1];count++;}catch(e){}});
        ok("EMU","TelephonyManager spoofado  ("+count+" métodos)");
    });
}

// ═══════════════════════════════════════════════════════════════════
//  4. HARDWARE KEYSTORE BYPASS (API 28)
// ═══════════════════════════════════════════════════════════════════
function hookKeystore() {
    section("Keystore bypass  (API 28)", "⬡");
    sh("KS","KeyInfo.isInsideSecureHardware",function(){Java.use("android.security.keystore.KeyInfo").isInsideSecureHardware.implementation=function(){ok("KS","isInsideSecureHardware → true");return true;};ok("KS","KeyInfo.isInsideSecureHardware → true");});
    sh("KS","setIsStrongBoxBacked",function(){Java.use("android.security.keystore.KeyGenParameterSpec$Builder").setIsStrongBoxBacked.implementation=function(){ok("KS","setIsStrongBoxBacked → false");return this.setIsStrongBoxBacked(false);};ok("KS","setIsStrongBoxBacked → sempre false");});
    sh("KS","PackageManager.hasSystemFeature",function(){
        var HW=["android.hardware.strongbox_keystore","android.hardware.keystore.app_attest_key","android.hardware.biometrics.face","android.hardware.fingerprint"];
        Java.use("android.content.pm.PackageManager").hasSystemFeature.overload("java.lang.String").implementation=function(f){for(var i=0;i<HW.length;i++)if(f===HW[i]){ok("KS","hasSystemFeature("+f+") → false");return false;}return this.hasSystemFeature(f);};
        ok("KS","hasSystemFeature  (strongbox · fingerprint · face · attest)");
    });
    sh("KS","KeyStoreException",function(){Java.use("java.security.KeyStoreException").$init.overload("java.lang.String").implementation=function(msg){if(msg&&(msg.indexOf("hardware")!==-1||msg.indexOf("StrongBox")!==-1||msg.indexOf("TEE")!==-1)){ok("KS","KeyStoreException silenciada");return this.$init("unavailable");}return this.$init(msg);};ok("KS","KeyStoreException silenciada");});
    sh("KS","KeyStore.load",function(){Java.use("java.security.KeyStore").load.overload("java.security.KeyStore$LoadStoreParameter").implementation=function(p){try{this.load(p);}catch(e){ok("KS","KeyStore.load silenciado");}};ok("KS","KeyStore.load silenciado");});
    sh("KS","KeyguardManager",function(){
        var KM=Java.use("android.app.KeyguardManager");
        KM.isDeviceSecure.overload().implementation=function(){ok("KS","isDeviceSecure → true");return true;};
        KM.isKeyguardSecure.overload().implementation=function(){return true;};
        ok("KS","KeyguardManager  (isDeviceSecure · isKeyguardSecure → true)");
    });
    sh("KS","FingerprintManager",function(){
        var FM=Java.use("android.hardware.fingerprint.FingerprintManager");
        FM.isHardwareDetected.implementation=function(){return false;};
        FM.hasEnrolledFingerprints.implementation=function(){return false;};
        ok("KS","FingerprintManager  (isHardwareDetected · hasEnrolledFingerprints)");
    });
    sh("KS","BiometricPrompt (API 28)",function(){Java.use("android.hardware.biometrics.BiometricPrompt").authenticate.overload("android.os.CancellationSignal","java.util.concurrent.Executor","android.hardware.biometrics.BiometricPrompt$AuthenticationCallback").implementation=function(){ok("KS","BiometricPrompt.authenticate interceptado");};ok("KS","BiometricPrompt.authenticate silenciado");});
    sh("KS","BiometricManager (Jetpack)",function(){Java.use("androidx.biometric.BiometricManager").canAuthenticate.overload("int").implementation=function(){return 0;};ok("KS","BiometricManager.canAuthenticate → SUCCESS(0)");});
    sh("KS","KeyPairGenerator attestation",function(){
        Java.use("java.security.KeyPairGenerator").generateKeyPair.implementation=function(){
            try{return this.generateKeyPair();}catch(e){if(e.message&&(e.message.indexOf("attestation")!==-1||e.message.indexOf("StrongBox")!==-1)){ok("KS","generateKeyPair attestation → RSA fallback");var kpg=Java.use("java.security.KeyPairGenerator").getInstance("RSA");kpg.initialize(2048);return kpg.generateKeyPair();}throw e;}
        };
        ok("KS","KeyPairGenerator.generateKeyPair  (attestation → RSA fallback)");
    });
}

// ═══════════════════════════════════════════════════════════════════
//  5. SSL PINNING BYPASS  (Zygisk-safe — SSLContext.init NÃO hookado)
// ═══════════════════════════════════════════════════════════════════
var _tm  = null;
var _ctx = null;

function buildTrustAll() {
    if (_tm) return;
    var X509TM = Java.use("javax.net.ssl.X509TrustManager");
    var SSLCtx  = Java.use("javax.net.ssl.SSLContext");
    var TA = Java.registerClass({ name:"noxdroid.v5.TrustAll", implements:[X509TM], methods:{checkClientTrusted:function(){},checkServerTrusted:function(){},getAcceptedIssuers:function(){return[];}} });
    _tm  = TA.$new();
    _ctx = SSLCtx.getInstance("TLS");
    _ctx.init(null, [_tm], null);
    ok("SSL","TrustAll criado");
}

function hookSSL() {
    section("SSL pinning bypass  (API 28 · Zygisk-safe)", "⬡");
    info("SSL", C.y + "SSLContext.init NÃO hookado" + C.rst + C.gr + " — Zygisk umount2(MNT_DETACH)" + C.rst);
    sh("SSL","TrustAll global",function(){buildTrustAll();});
    sh("SSL","SSLContext.getDefault",function(){Java.use("javax.net.ssl.SSLContext").getDefault.implementation=function(){return _ctx;};ok("SSL","SSLContext.getDefault → TrustAll");});
    sh("SSL","SSLContext.getInstance",function(){Java.use("javax.net.ssl.SSLContext").getInstance.overload("java.lang.String").implementation=function(proto){try{var c=this.getInstance(proto);c.init(null,[_tm],null);return c;}catch(e){return _ctx;}};ok("SSL","SSLContext.getInstance → TrustAll");});
    sh("SSL","HttpsURLConnection",function(){
        var AH=Java.registerClass({name:"noxdroid.v5.AllHosts",implements:[Java.use("javax.net.ssl.HostnameVerifier")],methods:{verify:function(){return true;}}});
        var H=Java.use("javax.net.ssl.HttpsURLConnection");
        H.setDefaultSSLSocketFactory(_ctx.getSocketFactory()); H.setDefaultHostnameVerifier(AH.$new());
        H.setDefaultHostnameVerifier.implementation=function(){}; H.setSSLSocketFactory.implementation=function(){}; H.setHostnameVerifier.implementation=function(){};
        ok("SSL","HttpsURLConnection defaults → TrustAll");
    });
    sh("SSL","SSLPeerUnverifiedException auto-patcher",function(){
        Java.use("javax.net.ssl.SSLPeerUnverifiedException").$init.implementation=function(str){
            ok("SSL","SSLPeerUnverifiedException → auto-patch");
            try{var st=Java.use("java.lang.Thread").currentThread().getStackTrace();for(var i=0;i<st.length;i++){if(st[i].getClassName()==="javax.net.ssl.SSLPeerUnverifiedException"&&i+1<st.length){var f=st[i+1];var cls=Java.use(f.getClassName());var meth=cls[f.getMethodName()];if(meth&&!meth.implementation){var rt=meth.returnType.type;meth.implementation=function(){return rt==="void"?undefined:null;};ok("SSL","Auto-patch: "+f.getClassName()+"."+f.getMethodName());}break;}}}catch(e){}
            return this.$init(str);
        };
        ok("SSL","SSLPeerUnverifiedException auto-patcher");
    });
    sh("SSL","TrustManagerImpl.checkTrustedRecursive",function(){Java.use("com.android.org.conscrypt.TrustManagerImpl").checkTrustedRecursive.implementation=function(){return Java.use("java.util.ArrayList").$new();};ok("SSL","TrustManagerImpl.checkTrustedRecursive");});
    sh("SSL","TrustManagerImpl.verifyChain (3 args)",function(){Java.use("com.android.org.conscrypt.TrustManagerImpl").verifyChain.overload("java.util.List","java.util.List","java.lang.String").implementation=function(u,ta,host){ok("SSL","verifyChain(3) → "+host);return u;};ok("SSL","TrustManagerImpl.verifyChain (3 args · API 28)");});
    sh("SSL","TrustManagerImpl.verifyChain (6 args)",function(){Java.use("com.android.org.conscrypt.TrustManagerImpl").verifyChain.overload("java.util.List","java.util.List","java.lang.String","boolean","[B","[B").implementation=function(u){return u;};ok("SSL","TrustManagerImpl.verifyChain (6 args · fallback)");});
    sh("SSL","TrustManagerImpl.checkServerTrusted (2)",function(){Java.use("com.android.org.conscrypt.TrustManagerImpl").checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;","java.lang.String").implementation=function(c){return Java.use("java.util.Arrays").asList(c);};ok("SSL","TrustManagerImpl.checkServerTrusted (2)");});
    sh("SSL","TrustManagerImpl.checkServerTrusted (3)",function(){Java.use("com.android.org.conscrypt.TrustManagerImpl").checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;","java.lang.String","java.lang.String").implementation=function(c,at,host){ok("SSL","checkServerTrusted(3) → "+host);return Java.use("java.util.Arrays").asList(c);};ok("SSL","TrustManagerImpl.checkServerTrusted (3)");});
    sh("SSL","OkHttp3 CertPinner (List)",   function(){Java.use("okhttp3.CertificatePinner").check.overload("java.lang.String","java.util.List").implementation=function(h){ok("SSL","CertPinner(List): "+h);};ok("SSL","OkHttp3 CertPinner (List)");});
    sh("SSL","OkHttp3 CertPinner (cert)",   function(){Java.use("okhttp3.CertificatePinner").check.overload("java.lang.String","java.security.cert.Certificate").implementation=function(h){ok("SSL","CertPinner(cert): "+h);};ok("SSL","OkHttp3 CertPinner (cert)");});
    sh("SSL","OkHttp3 CertPinner (Array)",  function(){Java.use("okhttp3.CertificatePinner").check.overload("java.lang.String","[Ljava.security.cert.Certificate;").implementation=function(h){ok("SSL","CertPinner(Array): "+h);};ok("SSL","OkHttp3 CertPinner (Array)");});
    sh("SSL","OkHttp3 CertPinner ($okhttp)",function(){Java.use("okhttp3.CertificatePinner")["check$okhttp"].implementation=function(h){ok("SSL","CertPinner.$okhttp: "+h);};ok("SSL","OkHttp3 CertPinner ($okhttp)");});
    sh("SSL","BasicCertificateChainCleaner", function(){Java.use("okhttp3.internal.tls.BasicCertificateChainCleaner").clean.implementation=function(c){return c;};ok("SSL","BasicCertificateChainCleaner.clean");});
    sh("SSL","OkHttpClient.Builder.certPinner",function(){Java.use("okhttp3.OkHttpClient$Builder").certificatePinner.implementation=function(){return this;};ok("SSL","OkHttpClient.Builder.certificatePinner → noop");});
    sh("SSL","OkHttpClient.Builder.sslSocketFactory",function(){Java.use("okhttp3.OkHttpClient$Builder").sslSocketFactory.overload("javax.net.ssl.SSLSocketFactory","javax.net.ssl.X509TrustManager").implementation=function(){ok("SSL","Builder.sslSocketFactory → TrustAll");return this.sslSocketFactory(_ctx.getSocketFactory(),_tm);};ok("SSL","OkHttpClient.Builder.sslSocketFactory");});
    sh("SSL","ConnectionSpec.isCompatible",function(){Java.use("okhttp3.ConnectionSpec").isCompatible.implementation=function(){return true;};ok("SSL","ConnectionSpec.isCompatible → true");});
    sh("SSL","ConscryptFileDescriptorSocket",function(){Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket").verifyCertificateChain.implementation=function(){ok("SSL","ConscryptFDS bypassed");};ok("SSL","ConscryptFileDescriptorSocket");});
    sh("SSL","ConscryptEngineSocket",function(){var c=Java.use("com.android.org.conscrypt.ConscryptEngineSocket");if(!c.verifyCertificateChain||!c.verifyCertificateChain.overloads)throw new Error("método ausente");c.verifyCertificateChain.overloads.forEach(function(o){o.implementation=function(){ok("SSL","ConscryptES bypassed");};});ok("SSL","ConscryptEngineSocket");});
    sh("SSL","OpenSSLSocketImpl (Conscrypt)",function(){Java.use("com.android.org.conscrypt.OpenSSLSocketImpl").verifyCertificateChain.implementation=function(){ok("SSL","OpenSSLSocketImpl bypassed");};ok("SSL","OpenSSLSocketImpl (Conscrypt)");});
    sh("SSL","OpenSSLSocketImpl (Harmony)", function(){Java.use("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl").verifyCertificateChain.implementation=function(){ok("SSL","Harmony bypassed");};ok("SSL","OpenSSLSocketImpl (Harmony)");});
    sh("SSL","Conscrypt Platform (Socket)", function(){Java.use("com.android.org.conscrypt.Platform").checkServerTrusted.overload("javax.net.ssl.X509TrustManager","[Ljava.security.cert.X509Certificate;","java.lang.String","com.android.org.conscrypt.AbstractConscryptSocket").implementation=function(){ok("SSL","Platform(Socket) bypassed");};ok("SSL","Conscrypt Platform (Socket)");});
    sh("SSL","Conscrypt Platform (Engine)", function(){Java.use("com.android.org.conscrypt.Platform").checkServerTrusted.overload("javax.net.ssl.X509TrustManager","[Ljava.security.cert.X509Certificate;","java.lang.String","com.android.org.conscrypt.ConscryptEngine").implementation=function(){ok("SSL","Platform(Engine) bypassed");};ok("SSL","Conscrypt Platform (Engine)");});
    sh("SSL","NSC.checkPins",function(){Java.use("android.security.net.config.NetworkSecurityTrustManager").checkPins.implementation=function(){ok("SSL","NSC.checkPins bypassed");};ok("SSL","NetworkSecurityTrustManager.checkPins");});
    sh("SSL","NSC.checkServerTrusted",function(){Java.use("android.security.net.config.NetworkSecurityTrustManager").checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;","java.lang.String").implementation=function(){ok("SSL","NSC.checkServerTrusted bypassed");};ok("SSL","NSC.checkServerTrusted");});
    sh("SSL","Pin.matches",function(){Java.use("android.security.net.config.Pin").matches.implementation=function(){return true;};ok("SSL","Pin.matches → true");});
    sh("SSL","PinSet.isExpired",function(){Java.use("android.security.net.config.PinSet").isExpired.implementation=function(){return false;};ok("SSL","PinSet.isExpired → false");});
    sh("SSL","WebViewClient.onReceivedSslError",function(){Java.use("android.webkit.WebViewClient").onReceivedSslError.overload("android.webkit.WebView","android.webkit.SslErrorHandler","android.net.http.SslError").implementation=function(wv,h,e){ok("SSL","WebViewClient → proceed()");h.proceed();};ok("SSL","WebViewClient.onReceivedSslError → proceed()");});
    sh("SSL","Trustkit",function(){Java.use("com.datatheorem.android.trustkit.pinning.PinningTrustManager").checkServerTrusted.implementation=function(){ok("SSL","Trustkit bypassed");};ok("SSL","Trustkit PinningTrustManager");});
    sh("SSL","Squareup CertPinner (cert)",function(){Java.use("com.squareup.okhttp.CertificatePinner").check.overload("java.lang.String","java.security.cert.Certificate").implementation=function(){};ok("SSL","Squareup CertPinner (cert)");});
    sh("SSL","Squareup CertPinner (list)",function(){Java.use("com.squareup.okhttp.CertificatePinner").check.overload("java.lang.String","java.util.List").implementation=function(){};ok("SSL","Squareup CertPinner (list)");});
    sh("SSL","Netty FingerprintTrustManager",function(){Java.use("io.netty.handler.ssl.util.FingerprintTrustManagerFactory").checkTrusted.implementation=function(){ok("SSL","Netty bypassed");};ok("SSL","Netty FingerprintTrustManagerFactory");});
    sh("SSL","Appmattus CertTransparency (2)",function(){Java.use("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager").checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;","java.lang.String").implementation=function(){};ok("SSL","Appmattus (2 args)");});
    sh("SSL","Appmattus CertTransparency (3)",function(){Java.use("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyTrustManager").checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;","java.lang.String","java.lang.String").implementation=function(){return Java.use("java.util.ArrayList").$new();};ok("SSL","Appmattus (3 args)");});
    sh("SSL","Apache AbstractVerifier",function(){Java.use("org.apache.http.conn.ssl.AbstractVerifier").verify.overload("java.lang.String","[Ljava.lang.String;","[Ljava.lang.String;","boolean").implementation=function(){};ok("SSL","Apache AbstractVerifier");});
    sh("SSL","Boye AbstractVerifier",function(){Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier").verify.implementation=function(){};ok("SSL","Boye AbstractVerifier");});
    sh("SSL","CWAC CertPinManager",function(){Java.use("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager").isChainValid.overload("java.lang.String","java.util.List").implementation=function(){return true;};ok("SSL","CWAC CertPinManager");});

    // Enumerações em threads daemon
    setTimeout(function(){Java.perform(function(){daemon("HVPatcher",function(){section("SSL HostnameVerifier scan","·");Java.enumerateLoadedClasses({onMatch:function(name){if(name.toLowerCase().indexOf("hostnameverifier")===-1)return;try{var cls=Java.use(name);if(cls.verify){cls.verify.implementation=function(){return true;};ok("SSL","HV patched: "+name);}}catch(e){}},onComplete:function(){ok("SSL","HostnameVerifier scan concluído");}});});});},CONFIG.HV_PATCH_DELAY);
    setTimeout(function(){Java.perform(function(){section("SSL Hilt post-startup patch","·");daemon("HiltPatcher",function(){Java.enumerateLoadedClasses({onMatch:function(name){if(name.toLowerCase().indexOf("trustmanager")===-1)return;try{var cls=Java.use(name);["checkServerTrusted","checkClientTrusted"].forEach(function(m){if(!cls[m])return;cls[m].overloads.forEach(function(ov){try{ov.implementation=function(){if(ov.returnType&&ov.returnType.className==="java.util.List")return Java.use("java.util.ArrayList").$new();};}catch(e){}});});if(cls.getAcceptedIssuers)try{cls.getAcceptedIssuers.implementation=function(){return[];};}catch(e){}ok("SSL","Hilt TM: "+name);}catch(e){}},onComplete:function(){ok("SSL","Hilt TrustManager scan concluído");}});});});},CONFIG.HILT_PATCH_DELAY+2000);
}

// ═══════════════════════════════════════════════════════════════════
//  6. HTTP INTERCEPT — OkHttp3 NoxInterceptor + URL.openConnection
// ═══════════════════════════════════════════════════════════════════
function hookHTTP() {
    section("HTTP intercept", "⬡");

    sh("HTTP","OkHttp3 NoxInterceptor",function(){
        var Interceptor3 = Java.use("okhttp3.Interceptor");
        var NoxInterceptor = Java.registerClass({
            name: "noxdroid.v5.NoxInterceptor",
            implements: [Interceptor3],
            methods: {
                intercept: function(chain) {
                    var req  = chain.request();
                    var url  = req.url().toString();
                    var meth = req.method();
                    var body = "";
                    try {
                        var rb = req.body();
                        if (rb) {
                            var buf = Java.use("okio.Buffer").$new();
                            rb.writeTo(buf);
                            body = buf.readUtf8();
                            if (body.length > CONFIG.MAX_BODY_LOG)
                                body = body.substring(0, CONFIG.MAX_BODY_LOG) + "…";
                        }
                    } catch(e) {}
                    info("HTTP", C.bg + meth + C.rst + " " + C.bw + url + C.rst);
                    if (body) info("HTTP", C.gr + "body: " + C.w + body + C.rst);

                    var resp = chain.proceed(req);
                    var code = resp.code();
                    var icon = (code >= 200 && code < 300) ? I.ok : I.warn;
                    info("HTTP", icon + " " + C.by + code + C.rst + " " + C.gr + url + C.rst);

                    if (CONFIG.HTTP_STACK) {
                        try {
                            var st = Java.use("java.lang.Thread").currentThread().getStackTrace();
                            var lines = [];
                            for (var i = 0; i < Math.min(st.length, 12); i++) {
                                var f = st[i];
                                var cn = f.getClassName();
                                if (cn.indexOf("noxdroid") !== -1) continue;
                                lines.push("  " + cn + "." + f.getMethodName() + ":" + f.getLineNumber());
                            }
                            if (lines.length) info("HTTP", C.gr + "stack:\n" + lines.join("\n") + C.rst);
                        } catch(e) {}
                    }
                    ok("HTTP", "interceptado");
                    return resp;
                }
            }
        });

        // Injeta o interceptor em todos os OkHttpClient criados
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        var Builder      = Java.use("okhttp3.OkHttpClient$Builder");
        Builder.build.implementation = function() {
            this.addInterceptor(NoxInterceptor.$new());
            return this.build();
        };
        ok("HTTP","OkHttp3 NoxInterceptor instalado");
    });

    sh("HTTP","URL.openConnection",function(){
        Java.use("java.net.URL").openConnection.overload().implementation = function() {
            var url = this.toString();
            info("HTTP", C.b + "openConnection: " + C.rst + C.bw + url + C.rst);
            return this.openConnection();
        };
        ok("HTTP","URL.openConnection hook");
    });

    sh("HTTP","HttpURLConnection.getResponseCode",function(){
        Java.use("java.net.HttpURLConnection").getResponseCode.implementation = function() {
            var code = this.getResponseCode();
            var url  = this.getURL ? this.getURL().toString() : "?";
            var icon = (code >= 200 && code < 300) ? I.ok : I.warn;
            info("HTTP", icon + " " + C.by + code + C.rst + " " + C.gr + url + C.rst);
            return code;
        };
        ok("HTTP","HttpURLConnection.getResponseCode hook");
    });
}

// ═══════════════════════════════════════════════════════════════════
//  7. SCREEN BYPASS — FLAG_SECURE, Window, SurfaceView, TextureView
// ═══════════════════════════════════════════════════════════════════
function hookScreen() {
    section("Screen bypass", "⬡");

    sh("SCREEN","Window.setFlags FLAG_SECURE",function(){
        Java.use("android.view.Window").setFlags.implementation = function(flags, mask) {
            var FLAG_SECURE = 0x00002000;
            if (flags & FLAG_SECURE) {
                ok("SCREEN","Window.setFlags FLAG_SECURE removido");
                flags = flags & ~FLAG_SECURE;
                mask  = mask  & ~FLAG_SECURE;
            }
            return this.setFlags(flags, mask);
        };
        ok("SCREEN","Window.setFlags hook");
    });

    sh("SCREEN","Window.addFlags FLAG_SECURE",function(){
        Java.use("android.view.Window").addFlags.implementation = function(flags) {
            var FLAG_SECURE = 0x00002000;
            if (flags & FLAG_SECURE) {
                ok("SCREEN","Window.addFlags FLAG_SECURE removido");
                flags = flags & ~FLAG_SECURE;
            }
            return this.addFlags(flags);
        };
        ok("SCREEN","Window.addFlags hook");
    });

    sh("SCREEN","PhoneWindow.setFlags",function(){
        Java.use("com.android.internal.policy.PhoneWindow").setFlags.implementation = function(flags, mask) {
            var FLAG_SECURE = 0x00002000;
            if (flags & FLAG_SECURE) {
                ok("SCREEN","PhoneWindow.setFlags FLAG_SECURE removido");
                flags = flags & ~FLAG_SECURE;
                mask  = mask  & ~FLAG_SECURE;
            }
            return this.setFlags(flags, mask);
        };
        ok("SCREEN","PhoneWindow.setFlags hook");
    });

    sh("SCREEN","SurfaceView.setSecure",function(){
        Java.use("android.view.SurfaceView").setSecure.implementation = function(secure) {
            if (secure) ok("SCREEN","SurfaceView.setSecure(true) → false");
            return this.setSecure(false);
        };
        ok("SCREEN","SurfaceView.setSecure hook");
    });

    sh("SCREEN","TextureView.setOpaque",function(){
        Java.use("android.view.TextureView").setOpaque.implementation = function(opaque) {
            return this.setOpaque(opaque);
        };
        ok("SCREEN","TextureView.setOpaque hook");
    });

    sh("SCREEN","Activity.getWindow",function(){
        Java.use("android.app.Activity").onResume.implementation = function() {
            try {
                var FLAG_SECURE = 0x00002000;
                var win = this.getWindow();
                var attrs = win.getAttributes();
                if (attrs.flags.value & FLAG_SECURE) {
                    attrs.flags.value = attrs.flags.value & ~FLAG_SECURE;
                    win.setAttributes(attrs);
                    ok("SCREEN","Activity.onResume FLAG_SECURE removido de " + this.getClass().getName());
                }
            } catch(e) {}
            return this.onResume();
        };
        ok("SCREEN","Activity.onResume FLAG_SECURE watcher");
    });
}

// ═══════════════════════════════════════════════════════════════════
//  INIT
// ═══════════════════════════════════════════════════════════════════
var _t0 = Date.now();

if (CONFIG.NATIVE_BYPASS) hookNative();

Java.perform(function() {
    banner();

    if (CONFIG.ROOT_BYPASS)        hookRoot();
    if (CONFIG.ADB_BYPASS)         hookAdb();
    if (CONFIG.EMULATOR_BYPASS)    hookEmulator();
    if (CONFIG.KEYSTORE_BYPASS)    hookKeystore();
    if (CONFIG.SSL_PINNING_BYPASS) hookSSL();
    if (CONFIG.HTTP_INTERCEPT)     hookHTTP();
    if (CONFIG.SCREEN_BYPASS)      hookScreen();

    summary(Date.now() - _t0);
});

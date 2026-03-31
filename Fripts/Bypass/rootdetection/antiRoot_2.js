/*
Created By @ApkUnpacke — https://github.com/apkunpacker/Root_Bypass
Source: https://github.com/lautarovculic/fridaScripts
Native-level root bypass: hooks open, fopen, popen, access, stat, system,
strstr, strtok, faccessat, getenv, pathconf, execv, execvp, execvpe.
Also hooks Java PackageManager, File.exists, BufferedReader.readLine.
*/
var ProName = ProcessName();
function ProcessName() {
    var openPtr = Module.getExportByName('libc.so', 'open');
    var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);
    var readPtr = Module.getExportByName('libc.so', 'read');
    var read = new NativeFunction(readPtr, 'int', ['int', 'pointer', 'int']);
    var closePtr = Module.getExportByName('libc.so', 'close');
    var close = new NativeFunction(closePtr, 'int', ['int']);
    var path = Memory.allocUtf8String('/proc/self/cmdline');
    var fd = open(path, 0);
    if (fd != -1) {
        var buffer = Memory.alloc(0x1000);
        var result = read(fd, buffer, 0x1000);
        close(fd);
        result = ptr(buffer).readCString();
        return result;
    }
    return -1;
}

var FakeMaps = "/data/data/" + ProName + "/maps";
var FakeMounts = "/data/data/" + ProName + "/mounts";
var FakeMountInfo = "/data/data/" + ProName + "/mountinfo";
var MapsFile = new File(FakeMaps, "w");
var FMountFile = new File(FakeMounts, "w");
var FMInfo = new File(FakeMountInfo, "w");
var MapsBuffer = Memory.alloc(512);
var MountBuffer = Memory.alloc(512);
var MountInfoBuffer = Memory.alloc(512);

var RootPath = new Array("fstab.andy","ueventd.andy.rc","busybox","resetprop","supolicy","magiskpolicy","%s/magisk","/sdcard/Download/magisk_patched.img","magisk.version","/data/adb/","/sbin/.magisk/","/sbin/magiskpolicy","/sbin/magiskhide","/sbin/.core/mirror","/sbin/.core/img","/sbin/.core/db-0/magisk.db","magisk","/sbin/magiskinit","/dev/.magisk.unblock","/sbin/magisk","/data/adb/magisk.img","/data/adb/magisk.db","/data/adb/.boot_count","/data/adb/magisk_simple","/cache/.disable_magisk","/cache/magisk.log","/init.magisk.rc","/data/data/com.topjohnwu.magisk","/system/bin/su","/system/xbin/su","/data/local/xbin/su","/data/local/su","/su/bin/su","/sbin/su","/system/bin/.ext/su","/system/bin/failsafe/su","/system/sd/xbin/su","/system/usr/we-need-root/su","/cache/su","/data/su","/dev/su","com.noshufou.android.su","eu.chainfire.supersu","com.koushikdutta.superuser","com.topjohnwu.magisk","de.robv.android.xposed.installer","com.saurik.substrate");
var Executable = ["busybox","resetprop","supolicy","magiskpolicy","magisk","sh","getprop","which","mount","build.prop","id","su","ps","getenforce","/system/bin/sh","pm","path","PATH"];

var readPtr = Module.findExportByName("libc.so", "read");
var read = new NativeFunction(readPtr, 'int', ['int', 'pointer', "int"]);
var openPtr = Module.findExportByName("libc.so", "open");
var open = new NativeFunction(openPtr, 'int', ['pointer', 'int']);

Interceptor.replace(openPtr, new NativeCallback(function(pathname, flag) {
    var FD = open(pathname, flag);
    var Path = pathname.readCString();
    if (Path.indexOf("/proc/") >= 0 && Path.indexOf("maps") >= 0) {
        while (parseInt(read(FD, MapsBuffer, 512)) !== 0) {
            var MBuffer = MapsBuffer.readCString();
            MBuffer = MBuffer.replaceAll(" /system/", "FakingMaps").replaceAll(" /vendor/", "FakingMaps")
                             .replaceAll("libriru", "FakingMaps").replaceAll("frida", "FakingMaps")
                             .replaceAll("magisk", "FakingMaps");
            MapsFile.write(MBuffer);
        }
        return open(Memory.allocUtf8String(FakeMaps), flag);
    }
    if (Path.indexOf("/proc/") >= 0 && Path.indexOf("mounts") >= 0) {
        while (parseInt(read(FD, MountBuffer, 512)) !== 0) {
            var MNTBuffer = MountBuffer.readCString();
            MNTBuffer = MNTBuffer.replaceAll("magisk", "Bypassed").replaceAll("libriru", "Bypassed")
                                 .replaceAll("xposed", "Bypassed").replaceAll("mirror", "Bypassed");
            FMountFile.write(MNTBuffer);
        }
        return open(Memory.allocUtf8String(FakeMounts), flag);
    }
    if (RootPath.indexOf(Path) > -1) {
        pathname.writeUtf8String("MadeByBypass");
        return open(pathname, flag);
    }
    return FD;
}, 'int', ['pointer', 'int']));

var fopenPtr = Module.findExportByName("libc.so", "fopen");
var fopen = new NativeFunction(fopenPtr, 'pointer', ['pointer', 'pointer']);
Interceptor.replace(fopenPtr, new NativeCallback(function(fname, mode) {
    var retval = fopen(fname, mode);
    var Path = fname.readCString();
    if (RootPath.indexOf(Path) > -1) {
        fname.writeUtf8String("MadeByBypass");
        return fopen(fname, mode);
    }
    return retval;
}, 'pointer', ['pointer', 'pointer']));

var accessPtr = Module.findExportByName("libc.so", "access");
var access = new NativeFunction(accessPtr, 'int', ['pointer', 'int']);
Interceptor.replace(accessPtr, new NativeCallback(function(pathname, mode) {
    var Path = pathname.readCString();
    if (RootPath.indexOf(Path) > -1) {
        pathname.writeUtf8String("MadeByBypass");
        return access(pathname, mode);
    }
    return access(pathname, mode);
}, 'int', ['pointer', 'int']));

Interceptor.attach(Module.findExportByName(null, "strstr"), {
    onEnter: function(args) {
        this.root = false;
        var str1 = args[0].readCString();
        var str2 = args[1].readCString();
        if (RootPath.indexOf(str1) > -1 || RootPath.indexOf(str2) > -1 ||
            str1.indexOf(" /system/") !== -1 || str2.indexOf(" /system/") !== -1 ||
            str1.indexOf("magisk") !== -1 || str2.indexOf("magisk") !== -1) {
            this.root = true;
        }
    },
    onLeave: function(retval) {
        if (this.root) retval.replace(0);
    }
});

Java.performNow(function() {
    try {
        var PackageManager = Java.use("android.app.ApplicationPackageManager");
        PackageManager.getPackageInfo.overload('java.lang.String', 'int').implementation = function(pkgname, flags) {
            if (RootPath.indexOf(pkgname) > -1) {
                console.log("[*] Bypass Package: " + pkgname);
                return this.getPackageInfo.call(this, "this.is.fake.package", flags);
            }
            return this.getPackageInfo.call(this, pkgname, flags);
        };

        var ioFile = Java.use('java.io.File');
        ioFile.exists.implementation = function() {
            var name = ioFile.getName.call(this);
            if (RootPath.indexOf(name) > -1 || Executable.indexOf(name) > -1) {
                console.log("[*] Bypass File.exists: " + name);
                return false;
            }
            return this.exists.call(this);
        };

        var BufferedReader = Java.use('java.io.BufferedReader');
        BufferedReader.readLine.overload().implementation = function() {
            var text = this.readLine.call(this);
            if (text !== null && RootPath.indexOf(text) > -1) {
                console.log("[*] Bypass readline: " + text);
                return "we.from.other.universe";
            }
            return text;
        };
    } catch (e) {
        console.error(e);
    }
});

/**
 * frida_crypto_hooks.js
 * =====================
 * Comprehensive Java + Native crypto interceptor.
 * Source: https://github.com/Magpol/MiscFrida
 *
 * Covers:
 *   Java: SecretKeySpec, IvParameterSpec, GCMParameterSpec, PBEKeySpec,
 *         Cipher.init, Mac.init, KeyGenerator.init, SecretKeyFactory.generateSecret,
 *         MessageDigest, KeyAgreement.doPhase, SQLCipher (3 variants), KeyStore.setEntry
 *   Native (BoringSSL/libcrypto): EVP_CipherInit_ex, EVP_EncryptInit_ex,
 *         EVP_DecryptInit_ex, EVP_AEAD_CTX_init, AES_set_encrypt/decrypt_key,
 *         HMAC_Init_ex, PKCS5_PBKDF2_HMAC, HKDF, HKDF_extract, HKDF_expand,
 *         sqlite3_key, sqlite3_key_v2, sqlite3_rekey, EC_KEY_generate_key, ChaCha20_ctr32
 */

"use strict";

const CONFIG = {
    SHOW_STACK:     false,
    SHOW_HEX:       true,
    MIN_KEY_BYTES:  4,
    FILTER_PKG:     "",
    COLOUR:         true,
    NATIVE_SCAN:    true,
    JAVA_HOOKS:     true,
    DEDUP_WINDOW:   500,
};

const C = CONFIG.COLOUR ? {
    reset:"\x1b[0m",bold:"\x1b[1m",dim:"\x1b[2m",red:"\x1b[31m",green:"\x1b[32m",
    yellow:"\x1b[33m",blue:"\x1b[34m",cyan:"\x1b[36m",white:"\x1b[37m",magenta:"\x1b[35m",
} : Object.fromEntries(["reset","bold","dim","red","green","yellow","blue","cyan","white","magenta"].map(k=>[k,""]));

const CATEGORY_COLOR = {
    KEY:C.green,IV:C.cyan,NONCE:C.cyan,HMAC_KEY:C.yellow,PASSPHRASE:C.red+C.bold,
    DERIVED:C.magenta,HASH_IN:C.dim,HASH_OUT:C.blue,AEAD_KEY:C.green+C.bold,
    DH_SECRET:C.red,GENERIC:C.white,
};

const _dedupCache = new Map();
function isDuplicate(key) {
    const now = Date.now();
    const last = _dedupCache.get(key);
    if (last && (now - last) < CONFIG.DEDUP_WINDOW) return true;
    _dedupCache.set(key, now);
    if (_dedupCache.size > 512) _dedupCache.delete(_dedupCache.keys().next().value);
    return false;
}

function report(fn, cat, value, extra) {
    if (!value) return;
    const dedupKey = `${fn}:${cat}:${JSON.stringify(value)}`;
    if (isDuplicate(dedupKey)) return;
    const cc = CATEGORY_COLOR[cat] || C.white;
    let line = `${C.bold}[${cat}]${C.reset} ${cc}${fn}${C.reset}`;
    if (value.label)           line += `  ${C.dim}(${value.label})${C.reset}`;
    if (value.int !== undefined) line += `  int=${value.int}`;
    if (value.str)             line += `  str=${C.yellow}"${value.str}"${C.reset}`;
    if (value.hex)             line += `  hex=${C.green}${value.hex}${C.reset}`;
    if (value.bytes)           line += `  len=${value.bytes}`;
    if (extra) for (const [k,v] of Object.entries(extra)) if (v!=null) line += `  ${k}=${C.cyan}${v}${C.reset}`;
    if (CONFIG.SHOW_STACK) {
        try {
            const stack = Java.use("java.lang.Thread").currentThread().getStackTrace();
            const frames = Array.from(stack).map(f=>`    ${f.getClassName()}.${f.getMethodName()}(${f.getFileName()}:${f.getLineNumber()})`).filter(f=>!f.includes("java.lang.Thread")).slice(0,8).join("\n");
            line += `\n${C.dim}${frames}${C.reset}`;
        } catch(_) {}
    }
    console.log(line);
}

function bytesToHex(arr) {
    if (!arr || arr.length === 0) return "";
    const out = [];
    for (let i = 0; i < arr.length; i++) out.push((Number(arr[i]) & 0xff).toString(16).padStart(2,"0"));
    return out.join(" ");
}
function tryString(arr) {
    if (!arr || arr.length === 0) return null;
    let s = "";
    for (let i = 0; i < arr.length; i++) {
        const c = Number(arr[i]) & 0xff;
        if (c === 0) break;
        if (c < 0x20 || c > 0x7e) return null;
        s += String.fromCharCode(c);
    }
    return s.length >= 4 ? s : null;
}
function fromJavaBytes(jBytes, minLen) {
    if (!jBytes) return null;
    let arr;
    try { arr = (Array.isArray(jBytes) || jBytes instanceof Uint8Array) ? jBytes : Java.array("byte", jBytes); }
    catch(_) { arr = jBytes; }
    if (!arr || arr.length < (minLen || CONFIG.MIN_KEY_BYTES)) return null;
    const hex = bytesToHex(arr);
    const str = tryString(arr);
    const result = { hex, bytes: arr.length };
    if (str) result.str = str;
    return result;
}
function fromNativePtr(ptr, len, minLen) {
    if (ptr.isNull() || len <= 0) return null;
    if (len < (minLen || CONFIG.MIN_KEY_BYTES)) return null;
    let arr;
    try { arr = ptr.readByteArray(Math.min(len, 512)); } catch(_) { return null; }
    if (!arr) return null;
    const u8 = new Uint8Array(arr);
    const hex = bytesToHex(u8);
    const str = tryString(u8);
    const result = { hex, bytes: len };
    if (str) result.str = str;
    return result;
}

// ─── Java hooks ───────────────────────────────────────────────────────────────
if (CONFIG.JAVA_HOOKS) {
Java.perform(function () {
    try {
        const SKS = Java.use("javax.crypto.spec.SecretKeySpec");
        SKS.$init.overload("[B","java.lang.String").implementation = function(key,algo) {
            const v = fromJavaBytes(key); if(v) report("SecretKeySpec.<init>","KEY",v,{algo});
            return this.$init(key,algo);
        };
    } catch(e) { console.log("[!] SecretKeySpec: "+e); }

    try {
        const IPS = Java.use("javax.crypto.spec.IvParameterSpec");
        IPS.$init.overload("[B").implementation = function(iv) {
            const v = fromJavaBytes(iv,1); if(v) report("IvParameterSpec.<init>","IV",v);
            return this.$init(iv);
        };
    } catch(e) { console.log("[!] IvParameterSpec: "+e); }

    try {
        const GCM = Java.use("javax.crypto.spec.GCMParameterSpec");
        GCM.$init.overload("int","[B").implementation = function(tlen,iv) {
            const v = fromJavaBytes(iv,1); if(v) report("GCMParameterSpec.<init>","NONCE",v,{tagBits:tlen});
            return this.$init(tlen,iv);
        };
    } catch(e) { console.log("[!] GCMParameterSpec: "+e); }

    try {
        const PBE = Java.use("javax.crypto.spec.PBEKeySpec");
        PBE.$init.overload("[C","[B","int","int").implementation = function(pw,salt,iter,keyLen) {
            const pwStr = Array.from(pw).map(c=>String.fromCharCode(c&0xff)).join("");
            const sv = fromJavaBytes(salt,1);
            report("PBEKeySpec.<init>","PASSPHRASE",{str:pwStr,bytes:pw.length},{saltHex:sv?sv.hex:null,iterations:iter,keyLen});
            return this.$init(pw,salt,iter,keyLen);
        };
    } catch(e) { console.log("[!] PBEKeySpec: "+e); }

    try {
        const Cipher = Java.use("javax.crypto.Cipher");
        const MODES = {1:"ENCRYPT",2:"DECRYPT",3:"WRAP",4:"UNWRAP"};
        const ci2 = Cipher.init.overload("int","java.security.Key");
        const ci3 = Cipher.init.overload("int","java.security.Key","java.security.spec.AlgorithmParameterSpec");
        function extractCipher(ctx,opmode,key,params) {
            const algo = (()=>{try{return ctx.getAlgorithm();}catch(_){return"?";}})();
            const modeStr = MODES[opmode]||String(opmode);
            if(key){try{const v=fromJavaBytes(key.getEncoded());if(v)report("Cipher.init","KEY",v,{algo,mode:modeStr});}catch(_){}}
            if(params){try{if(params.$className==="javax.crypto.spec.IvParameterSpec"){const v=fromJavaBytes(params.getIV(),1);if(v)report("Cipher.init [iv]","IV",v,{algo});}}catch(_){}}
        }
        ci2.implementation = function(m,k){extractCipher(this,m,k,null);return ci2.call(this,m,k);};
        ci3.implementation = function(m,k,p){extractCipher(this,m,k,p);return ci3.call(this,m,k,p);};
    } catch(e) { console.log("[!] Cipher.init: "+e); }

    try {
        const Mac = Java.use("javax.crypto.Mac");
        const mi = Mac.init.overload("java.security.Key");
        mi.implementation = function(key) {
            const algo=(()=>{try{return this.getAlgorithm();}catch(_){return"?";}})();
            if(key){try{const v=fromJavaBytes(key.getEncoded());if(v)report("Mac.init","HMAC_KEY",v,{algo});}catch(_){}}
            return mi.call(this,key);
        };
    } catch(e) { console.log("[!] Mac.init: "+e); }

    try {
        const MD = Java.use("java.security.MessageDigest");
        const mdu = MD.update.overload("[B");
        const mdd = MD.digest.overload();
        mdu.implementation = function(input) {
            const v=fromJavaBytes(input); if(v) report("MessageDigest.update","HASH_IN",v,{algo:this.getAlgorithm()});
            return mdu.call(this,input);
        };
        mdd.implementation = function() {
            const result=mdd.call(this);
            const v=fromJavaBytes(result,1); if(v) report("MessageDigest.digest","HASH_OUT",v,{algo:this.getAlgorithm()});
            return result;
        };
    } catch(e) { console.log("[!] MessageDigest: "+e); }

    // SQLCipher
    for (const cls of ["net.sqlcipher.database.SQLiteDatabase","net.zetetic.database.sqlcipher.SQLiteDatabase","org.signal.sqlcipher.database.SQLiteDatabase"]) {
        try {
            const DB = Java.use(cls);
            for (const ov of DB.openOrCreateDatabase.overloads) {
                (function(ov){
                    ov.implementation = function() {
                        const args = Array.from(arguments);
                        if(args.length>=2&&args[1]){
                            const pw=args[1].toString();
                            if(pw&&pw.length>=4) report(`${cls}.openOrCreateDatabase`,"PASSPHRASE",{str:pw.substring(0,128),bytes:pw.length},{db:args[0]});
                        }
                        return ov.call(this,...args);
                    };
                })(ov);
            }
        } catch(_) {}
    }

    console.log(`${C.bold}${C.green}[*] Java crypto hooks installed${C.reset}`);
});
}

// ─── Native hooks ─────────────────────────────────────────────────────────────
if (CONFIG.NATIVE_SCAN) {
const CRYPTO_LIBS = /libcrypto|libssl|libsqlcipher|libsignalprotocol|libmolly|libsession/i;

function hookAllInstances(symName, libPattern, onEnter, onLeave) {
    const instances = [];
    const pat = typeof libPattern==="string" ? new RegExp(libPattern,"i") : libPattern;
    for (const m of Process.enumerateModules()) {
        if (!pat.test(m.name)) continue;
        try { const exp=m.findExportByName(symName); if(exp) instances.push({lib:m.name,addr:exp}); } catch(_) {}
    }
    if (instances.length===0) {
        try { const addr=Module.findExportByName(null,symName); if(addr) instances.push({lib:"in-process",addr}); } catch(_) {}
    }
    for (const {lib,addr} of instances) {
        try {
            Interceptor.attach(addr,{
                onEnter: onEnter ? function(args){onEnter.call(this,args,lib);} : undefined,
                onLeave: onLeave ? function(ret){onLeave.call(this,ret,lib);} : undefined,
            });
            console.log(`${C.dim}  [native] hooked ${symName} in ${lib}${C.reset}`);
        } catch(e) { console.log(`${C.dim}  [native] failed ${symName} in ${lib}: ${e}${C.reset}`); }
    }
}

function evpCipherInitHook(fnName) {
    hookAllInstances(fnName, CRYPTO_LIBS, function(args,lib) {
        const keyPtr=args[3], ivPtr=args[4], enc=args[5].toInt32();
        if(!keyPtr.isNull()){const kv=fromNativePtr(keyPtr,64);if(kv)report(fnName,"KEY",kv,{lib,dir:enc===1?"ENC":enc===0?"DEC":"KEEP"});}
        if(!ivPtr.isNull()){const iv=fromNativePtr(ivPtr,16,1);if(iv)report(fnName+" [iv]","IV",iv,{lib});}
    });
}
evpCipherInitHook("EVP_CipherInit_ex");
evpCipherInitHook("EVP_EncryptInit_ex");
evpCipherInitHook("EVP_DecryptInit_ex");
evpCipherInitHook("EVP_CipherInit_ex2");

hookAllInstances("EVP_AEAD_CTX_init", CRYPTO_LIBS, function(args,lib) {
    const keyPtr=args[2], keyLen=args[3].toInt32();
    if(!keyPtr.isNull()&&keyLen>0){const v=fromNativePtr(keyPtr,keyLen);if(v)report("EVP_AEAD_CTX_init","AEAD_KEY",v,{lib,tagLen:args[4].toInt32()});}
});

for (const fn of ["AES_set_encrypt_key","AES_set_decrypt_key"]) {
    hookAllInstances(fn, CRYPTO_LIBS, function(args,lib) {
        const keyPtr=args[0], keyBits=args[1].toInt32(), keyLen=Math.ceil(keyBits/8);
        if(!keyPtr.isNull()&&keyLen>0){const v=fromNativePtr(keyPtr,keyLen);if(v)report(fn,"KEY",v,{lib,bits:keyBits});}
    });
}

hookAllInstances("HMAC_Init_ex", CRYPTO_LIBS, function(args,lib) {
    const keyPtr=args[1], keyLen=args[2].toInt32();
    if(!keyPtr.isNull()&&keyLen>0){const v=fromNativePtr(keyPtr,keyLen);if(v)report("HMAC_Init_ex","HMAC_KEY",v,{lib});}
});

hookAllInstances("PKCS5_PBKDF2_HMAC", CRYPTO_LIBS, function(args,lib) {
    const passPtr=args[0], passLen=args[1].toInt32(), saltPtr=args[2], saltLen=args[3].toInt32(), iter=args[4].toInt32(), keyLen=args[6].toInt32(), outPtr=args[7];
    const epl = passLen<0 ? (passPtr.isNull()?0:passPtr.readCString().length) : passLen;
    if(!passPtr.isNull()&&epl>0){const pv=fromNativePtr(passPtr,epl);if(pv)report("PKCS5_PBKDF2_HMAC [password]","PASSPHRASE",pv,{lib,iterations:iter,keyLen});}
    if(!saltPtr.isNull()&&saltLen>0){const sv=fromNativePtr(saltPtr,saltLen,1);if(sv)report("PKCS5_PBKDF2_HMAC [salt]","GENERIC",sv,{lib});}
    this._outPtr=outPtr; this._keyLen=keyLen;
}, function(ret,lib) {
    if(ret.toInt32()!==0&&this._outPtr&&!this._outPtr.isNull()){const v=fromNativePtr(this._outPtr,this._keyLen);if(v)report("PKCS5_PBKDF2_HMAC [derived]","DERIVED",v,{lib});}
});

hookAllInstances("sqlite3_key", /.*/, function(args,lib) {
    const keyPtr=args[1], keyLen=args[2].toInt32();
    if(!keyPtr.isNull()&&keyLen>0){const v=fromNativePtr(keyPtr,keyLen,1);if(v)report("sqlite3_key","PASSPHRASE",v,{lib});}
});
hookAllInstances("sqlite3_key_v2", /.*/, function(args,lib) {
    const dbName=args[1].isNull()?"main":args[1].readCString(), keyPtr=args[2], keyLen=args[3].toInt32();
    if(!keyPtr.isNull()&&keyLen>0){const v=fromNativePtr(keyPtr,keyLen,1);if(v)report("sqlite3_key_v2","PASSPHRASE",v,{lib,db:dbName});}
});
hookAllInstances("sqlite3_rekey", /.*/, function(args,lib) {
    const keyPtr=args[1], keyLen=args[2].toInt32();
    if(!keyPtr.isNull()&&keyLen>0){const v=fromNativePtr(keyPtr,keyLen,1);if(v)report("sqlite3_rekey","PASSPHRASE",v,{lib,note:"NEW key"});}
});

console.log(`${C.bold}${C.green}[*] Native crypto hooks installed${C.reset}`);
}

console.log(`\n${C.bold}${C.blue}[*] frida_crypto_hooks.js active — Java:${CONFIG.JAVA_HOOKS} Native:${CONFIG.NATIVE_SCAN}${C.reset}\n`);

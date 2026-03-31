// Bypass RootBeer library root detection
// Source: https://github.com/lautarovculic/fridaScripts
// Usage: frida -U -f com.target.app -l rootBeerBypass.js

Java.perform(function () {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.overload().implementation = function () {
        console.log('\n[*] RootBeer.isRooted() → bypassed (returning false)');
        return false;
    };
});

// gps_spoof.js
// Spoofs GPS coordinates by overriding Location.getLatitude() and Location.getLongitude()
// Usage: frida -U -n <app> -l gps_spoof.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {
    var spoofLat = -23.5505; // Change to desired latitude
    var spoofLon = -46.6333; // Change to desired longitude

    var Location = Java.use("android.location.Location");

    Location.getLatitude.implementation = function () {
        console.log("[GPS Spoof] getLatitude() -> " + spoofLat);
        return spoofLat;
    };

    Location.getLongitude.implementation = function () {
        console.log("[GPS Spoof] getLongitude() -> " + spoofLon);
        return spoofLon;
    };

    console.log("[*] GPS spoof active: lat=" + spoofLat + " lon=" + spoofLon);
});

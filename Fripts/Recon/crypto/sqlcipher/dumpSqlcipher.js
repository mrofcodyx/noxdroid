// dumpSqlcipher.js
// Dumps a SQLCipher-encrypted database to plaintext using sqlcipher_export()
// Usage: frida -U -n <app> -l dumpSqlcipher.js
// Source: https://github.com/Magpol/MiscFrida

Java.perform(function () {
    var random_name = function (length) {
        var result = '';
        var characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        var charactersLength = characters.length;
        for (var i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    };

    Java.choose("net.zetetic.database.sqlcipher.SQLiteDatabase", {
        onMatch: function (instance) {
            var String = Java.use('java.lang.String');
            var testArray = Java.use("java.util.HashMap");
            let Obj = [];

            console.log("[*] DB path: " + instance.getPath());
            console.log("[*] isOpen: " + instance.isOpen());
            let tables = instance.getSyncedTables();
            console.log("[*] Tables: " + Java.cast(tables, testArray));
            console.log("[*] isReadOnly: " + instance.isReadOnly());

            var dbName = random_name(5);
            var sql1 = String.$new("ATTACH DATABASE '/data/user/0/com.random/databases/" + dbName + ".sql.plaintext' as " + dbName + " KEY '';");
            var sql2 = String.$new("SELECT sqlcipher_export('" + dbName + "');");
            var sql3 = String.$new("DETACH DATABASE " + dbName);

            instance.rawExecSQL(sql1, Obj);
            instance.rawExecSQL(sql2, Obj);
            instance.rawExecSQL(sql3, Obj);

            console.log("[+] Exported plaintext DB as: " + dbName + ".sql.plaintext");
        },
        onComplete: function () {
            console.log("[*] SQLCipher dump complete.");
        }
    });
});

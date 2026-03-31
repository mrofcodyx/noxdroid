// createNotification.js
// Creates a system notification from Frida context — useful for confirming code execution
// Usage: frida -U -n <app> -l createNotification.js
// Source: https://github.com/lautarovculic/fridaScripts

Java.perform(function () {
    var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
    var NotificationManager = Java.use("android.app.NotificationManager");
    var NotificationCompat = Java.use("androidx.core.app.NotificationCompat");
    var NotificationChannel = Java.use("android.app.NotificationChannel");

    var CHANNEL_ID = "frida_channel";
    var CHANNEL_NAME = "Frida Notifications";
    var NOTIF_ID = 1337;

    try {
        // Create notification channel (required for Android 8+)
        var channel = NotificationChannel.$new(CHANNEL_ID, CHANNEL_NAME, 3 /* IMPORTANCE_DEFAULT */);
        var nm = Java.cast(context.getSystemService("notification"), NotificationManager);
        nm.createNotificationChannel(channel);

        // Build notification
        var builder = NotificationCompat.Builder.$new(context, CHANNEL_ID);
        builder.setSmallIcon(0x01080020); // android.R.drawable.ic_dialog_info
        builder.setContentTitle("Frida");
        builder.setContentText("Script injected successfully");
        builder.setPriority(0);

        nm.notify(NOTIF_ID, builder.build());
        console.log("[*] Notification sent.");
    } catch (e) {
        console.log("[-] Notification failed: " + e);
        console.log("    (Try using NotificationManager directly or check channel support)");
    }
});

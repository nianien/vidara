Java.perform(function () {
    console.log("[*] Frida injected, monitoring video URLs...");

    function hit(url) {
        try {
            var s = url.toString();
            if (
                s.indexOf(".m3u8") !== -1 ||
                s.indexOf(".ts") !== -1 ||
                s.indexOf("mpegurl") !== -1 ||
                s.indexOf("__token__") !== -1
            ) {
                console.log("\n[FOUND] " + s);
            }
        } catch (e) {}
    }

    // 1️⃣ ExoPlayer MediaItem（上游，干净）
    try {
        var MediaItemBuilder = Java.use("com.google.android.exoplayer2.MediaItem$Builder");
        MediaItemBuilder.setUri.overload("android.net.Uri").implementation = function (uri) {
            hit(uri);
            return this.setUri(uri);
        };
        console.log("[+] Hooked MediaItem$Builder.setUri");
    } catch (e) {}

    // 2️⃣ HTTP DataSource（下游，必经点，最稳）
    try {
        var DS = Java.use("com.google.android.exoplayer2.upstream.DefaultHttpDataSource");
        DS.open.overload("com.google.android.exoplayer2.upstream.DataSpec").implementation = function (spec) {
            hit(spec.uri.value);
            return this.open(spec);
        };
        console.log("[+] Hooked DefaultHttpDataSource.open");
    } catch (e) {}

    // 3️⃣ OkHttpDataSource（部分构建会用）
    try {
        var OK = Java.use("com.google.android.exoplayer2.ext.okhttp.OkHttpDataSource");
        OK.open.overload("com.google.android.exoplayer2.upstream.DataSpec").implementation = function (spec) {
            hit(spec.uri.value);
            return this.open(spec);
        };
        console.log("[+] Hooked OkHttpDataSource.open");
    } catch (e) {}
});
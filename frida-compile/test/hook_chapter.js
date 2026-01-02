Java.perform(function () {
    console.log("[*] Hook Body.apply + RealCall (REQUEST DEDUP)");


    // =========================
    // 2️⃣ OkHttp 层：按 request.toString() 去重
    // =========================
    var TARGETS = [
        "/hwycclientreels/chapter/list",
        "/hwycclientreels/chapter/load"
    ];
    var RealCall = Java.use("okhttp3.internal.connection.RealCall");
    var getResp = RealCall.getResponseWithInterceptorChain$okhttp.overload();

    // ✅ 去重容器
    var seenReq = {}; // key = request.toString()

    getResp.implementation = function () {
        var req = this.request();
        var reqStr = req ? req.toString() : "";
        if (!TARGETS.some(function (t) {
            return reqStr.indexOf(t) !== -1;
        })) {
            return getResp.call(this);
        }

        // ✅ 去重判断
        if (seenReq[reqStr]) {
            // 已见过：不打印，直接放行
            return getResp.call(this);
        }
        seenReq[reqStr] = true;


        var resp = getResp.call(this);


        try {
            var body = resp.d();
            var mt = body.contentType();
            var ct = mt ? mt.toString() : "";
            if (ct.indexOf("application/json") === -1) return resp;
            if (body) {
                var text = body.string();
                if (text.indexOf("m3u8") === -1) return resp;
                // === 首次命中才打印 ===
                console.log("\n[HIT REQUEST]");
                console.log(reqStr);
                console.log("[HIT RESPONSE]");
                console.log("[BODY]\n" + text);
            }
        } catch (e) {
            console.log("[BODY ERROR] " + e);
        }

        return resp;
    };

    console.log("[READY] Hook installed (request dedup enabled)");
});
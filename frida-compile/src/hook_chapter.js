import Java from "frida-java-bridge";

Java.perform(function () {
    console.log("[*] Hook Body.apply + RealCall (REQUEST DEDUP)");


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

        console.log("[HIT RESPONSE]");
        try {
            var body = resp.d();
            if (body) {
                var mt = body.contentType();
                var ct = mt ? mt.toString() : "";
                if (ct.indexOf("application/json") === -1) return resp;
                var text = body.string();
                if (text.indexOf("m3u8") === -1) return resp;
                console.log("\n[HIT REQUEST]");
                console.log(reqStr);
                console.log("[HIT RESPONSE]");
                console.log("[BODY]\n" + text);
                // 发送消息到 Python 端
                send({
                    type: "goodshort",
                    data: text
                });
            }
        } catch (e) {
            console.log("[BODY ERROR] " + e);
        }
        return resp;
    };

    console.log("[READY] Hook installed (request dedup enabled)");
});
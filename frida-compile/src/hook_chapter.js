import Java from "frida-java-bridge";

Java.perform(function () {
    console.log("[*] Hook Body.apply + RealCall (REQUEST DEDUP)");

    // =========================
    // 1️⃣ Retrofit 参数层：改 latestChapterId = 0（保持你已验证版本）
    // =========================
    var BodyHandler = Java.use("retrofit2.ParameterHandler$Body");
    var MapCls = Java.use("java.util.Map");

    var origApply = BodyHandler.apply.overload(
        "retrofit2.RequestBuilder",
        "java.lang.Object"
    );

    origApply.implementation = function (rb, value) {
        if (value && MapCls.class.isInstance(value)) {
            var map = Java.cast(value, MapCls);
            if (map.containsKey("latestChapterId")) {
                var oldVal = map.get("latestChapterId");
                if (oldVal !== null && ("" + oldVal) !== "0") {
                    map.put("latestChapterId", Java.use("java.lang.Integer").valueOf(0));
                    console.log("[PATCH] latestChapterId " + oldVal + " -> 0");
                }
            }
        }
        return origApply.call(this, rb, value);
    };

    // =========================
    // 2️⃣ OkHttp 层：按 request.toString() 去重
    // =========================
    var TARGET = "/hwycclientreels/chapter/list";
    var RealCall = Java.use("okhttp3.internal.connection.RealCall");
    var getResp = RealCall.getResponseWithInterceptorChain$okhttp.overload();

    // ✅ 去重容器
    var seenReq = {}; // key = request.toString()

    getResp.implementation = function () {
        var req = this.request();
        var reqStr = req ? req.toString() : "";

        // 非目标接口，直接放行
        if (reqStr.indexOf(TARGET) === -1) {
            return getResp.call(this);
        }

        // ✅ 去重判断
        if (seenReq[reqStr]) {
            // 已见过：不打印，直接放行
            return getResp.call(this);
        }
        seenReq[reqStr] = true;

        // === 首次命中才打印 ===
        console.log("\n[HIT REQUEST]");
        console.log(reqStr);

        var resp = getResp.call(this);

        console.log("[HIT RESPONSE]");
        try {
            var body = resp.d();
            if (body) {
                var text = body.string();
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
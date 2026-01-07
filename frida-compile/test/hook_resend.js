Java.perform(function () {
    var RealCall = Java.use("okhttp3.internal.connection.RealCall");
    var getResp = RealCall.getResponseWithInterceptorChain$okhttp.overload();

    var CallbackIntf = Java.use("okhttp3.Callback");

    function findMethod(obj, paramTypeNames, retTypeNameOrNull) {
        var cls = obj.getClass();
        var ms = cls.getDeclaredMethods();
        for (var i = 0; i < ms.length; i++) {
            var m = ms[i];
            m.setAccessible(true);
            var ps = m.getParameterTypes();
            if (ps.length !== paramTypeNames.length) continue;

            var ok = true;
            for (var j = 0; j < ps.length; j++) {
                if (ps[j].getName() !== paramTypeNames[j]) {
                    ok = false;
                    break;
                }
            }
            if (!ok) continue;

            if (retTypeNameOrNull) {
                var rn = m.getReturnType().getName();
                if (rn !== retTypeNameOrNull) continue;
            }
            return m;
        }
        return null;
    }

    function findClientFromRealCall(callObj) {
        var cls = callObj.getClass();
        var fs = cls.getDeclaredFields();
        for (var i = 0; i < fs.length; i++) {
            var f = fs[i];
            f.setAccessible(true);
            try {
                // 只要字段类型是 OkHttpClient
                if (f.getType().getName() === "okhttp3.OkHttpClient") {
                    return f.get(callObj);
                }
            } catch (e) {
            }
        }
        return null;
    }

    // 你这版 Request: i() -> Request$Builder, d(String)->String
    function getHeader(req, name) {
        try {
            return req.d(name);
        } catch (e) {
            return null;
        }
    }

    // 反射：在 Response$Builder 上按签名找
    // 1) (okhttp3.ResponseBody) -> okhttp3.Response$Builder
    // 2) () -> okhttp3.Response
    function setBodyAndBuild(builderObj, newBodyObj) {
        var cls = builderObj.getClass();
        var methods = cls.getDeclaredMethods();

        var setBodyM = null;
        var buildM = null;

        for (var i = 0; i < methods.length; i++) {
            var m = methods[i];
            m.setAccessible(true);

            var ptypes = m.getParameterTypes();
            var rname = m.getReturnType().getName();

            if (!setBodyM &&
                ptypes.length === 1 &&
                ptypes[0].getName() === "okhttp3.ResponseBody" &&
                rname === "okhttp3.Response$Builder") {
                setBodyM = m;
            }

            if (!buildM &&
                ptypes.length === 0 &&
                rname === "okhttp3.Response") {
                buildM = m;
            }

            if (setBodyM && buildM) break;
        }

        if (!setBodyM) throw new Error("Builder method not found: (ResponseBody)->Builder");
        if (!buildM) throw new Error("Builder method not found: ()->Response");

        setBodyM.invoke(builderObj, Java.array("java.lang.Object", [newBodyObj]));
        return buildM.invoke(builderObj, Java.array("java.lang.Object", []));
    }

    function buildMarkedRequest(req) {
        var builder = req.i(); // 你反射里确认过：Request.i() -> Request$Builder

        // 找 (String,String)->Request$Builder
        var setHeaderM = findMethod(builder,
            ["java.lang.String", "java.lang.String"],
            "okhttp3.Request$Builder"
        );

        // 找 ()->okhttp3.Request
        var buildM = findMethod(builder, [], "okhttp3.Request");

        if (!setHeaderM) throw new Error("Request$Builder: (String,String)->Builder not found");
        if (!buildM) throw new Error("Request$Builder: ()->Request not found");

        setHeaderM.invoke(builder, Java.array("java.lang.Object", ["X-Frida-Resent", "1"]));
        return buildM.invoke(builder, Java.array("java.lang.Object", []));
    }

    var MyCallback = Java.registerClass({
        name: "com.frida.MyCallback_" + Date.now(),
        implements: [CallbackIntf],
        methods: {
            onFailure: function (call, e) {
                console.log("[RESENT] fail: " + e);
            },
            onResponse: function (call, response) {
                try {
                    // 你这版 Response: m() 是 code
                    console.log("[RESENT] ok code=" + response.m());
                    response.close();
                } catch (ex) {
                    console.log("[RESENT] resp handle err: " + ex);
                }
            }
        }
    });

    var JString = Java.use("java.lang.String");
    var ResponseBody = Java.use("okhttp3.ResponseBody");
    getResp.implementation = function () {
        var req = null;
        try {
            req = this.request();
        } catch (e) {
        }
        var reqStr = req ? req.toString() : "";

        if (reqStr.indexOf("/hwycclientreels/chapter/load") === -1) {
            return getResp.call(this);
        }

        // 防递归：重发的请求直接放行
        var resent = req ? getHeader(req, "X-Frida-Resent") : null;
        if (resent === "1") {
            console.log("\n[REQ@OkHttp] " + reqStr);
            var resp = getResp.call(this);
            var body = resp.d(); // Response.d() -> ResponseBody（你 dump 里确认）
            var bytes = body.bytes(); // ⚠️ 消费原 body
            var text = JString.$new(bytes, "UTF-8");

            console.log("\n[REQ@OkHttp] " + reqStr);
            console.log("[BODY]\n" + text);
            // ResponseBody.create(MediaType, byte[])
            var contentType = body.contentType();
            var createFn = ResponseBody.create.overload("okhttp3.MediaType", "[B");
            var newBody = createFn.call(ResponseBody, contentType, bytes);

            var builder = resp.d0();
            // 把 newBody 塞回 builder，再 build 新 Response
            var newResp = setBodyAndBuild(builder, newBody);
            return newResp;
        }

        // 先让原请求正常跑
        var resp = getResp.call(this);

        // 再重发
        try {
            console.log("[RESENT] start: " + reqStr);

            var client = findClientFromRealCall(this);
            if (!client) throw new Error("RealCall has no OkHttpClient field");

            // 反射找 client 的 (Request)->Call
            var newCallM = findMethod(client, ["okhttp3.Request"], "okhttp3.Call");
            if (!newCallM) throw new Error("OkHttpClient: (Request)->Call method not found");

            var newReq = buildMarkedRequest(req);

            // invoke 得到 okhttp3.Call
            var callObj = newCallM.invoke(client, Java.array("java.lang.Object", [newReq]));
            if (!callObj) throw new Error("newCall invoke returned null");

            // 反射找 call 的 (Callback)->void
            var enqueueM = findMethod(callObj, ["okhttp3.Callback"], "void");
            if (!enqueueM) throw new Error("Call: (Callback)->void method not found");

            enqueueM.invoke(callObj, Java.array("java.lang.Object", [MyCallback.$new()]));

            console.log("[RESENT] triggered OK");
        } catch (e) {
            console.log("[RESENT] error: " + e);
        }

        return resp;
    };

    console.log("[OK] hook RealCall.getResponseWithInterceptorChain$okhttp (resend via reflection)");
});
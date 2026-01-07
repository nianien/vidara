'use strict';

Java.perform(function () {
    const Log = Java.use('android.util.Log');
    const Exception = Java.use('java.lang.Exception');
    const List = Java.use('java.util.List');
    const ArrayList = Java.use('java.util.ArrayList');
    const Long = Java.use('java.lang.Long');
    const Integer = Java.use('java.lang.Integer');
    const Boolean = Java.use('java.lang.Boolean');
    const Gson = Java.use('com.google.gson.Gson').$new();
    const HashMap = Java.use('java.util.HashMap');
    const BooleanCls = Java.use('java.lang.Boolean');
    const Retrofit = Java.use('retrofit2.Retrofit');
    const Proxy = Java.use('java.lang.reflect.Proxy');

    const Map = Java.use('java.util.Map');

    const st = () => Log.getStackTraceString(Exception.$new());

    const safeStr = (v) => {
        try {
            return v ? v.toString() : '';
        } catch (_) {
            return '';
        }
    };

    function getByPath(o, path) {
        if (!o || !path) return null;

        const parts = path.replace(/\[(\d+)\]/g, '.$1').split('.');

        let cur = o;
        let lastKey = null;

        for (let i = 0; i < parts.length; i++) {
            const k = parts[i];
            if (!k) continue;

            if (cur == null || typeof cur !== 'object' || !(k in cur)) return null;

            lastKey = k;
            cur = cur[k];
        }

        return {k: lastKey, v: cur};
    }

    function show(obj, fields) {
        if (!obj) return '{}';
        const map = JSON.parse(Gson.toJson(obj));
        const out = {};
        for (let i = 0; i < fields.length; i++) {
            const p = fields[i];
            const kv = getByPath(map, p);
            if (kv) out[kv.k] = kv.v;
        }

        return JSON.stringify(out);
    }

    function showChapters(body) {
        if (!body) return [];

        // Java 对象 → JSON → JS Object
        const root = JSON.parse(Gson.toJson(body));
        const list = root && root.data && Array.isArray(root.data.list) ? root.data.list : [];

        const out = [];

        for (let i = 0; i < list.length; i++) {
            const c = list[i];
            if (!c) continue;

            out.push({
                id: c.id, bookId: c.bookId, chapterName: c.chapterName, cdn: c.cdn
            });
        }
        return JSON.stringify(out);
    }

    // 过滤规则
    const TARGETS = [
        // '/chapter/load',
        // '/chapter/list',
        '/book/quick/open'
    ];

    function hit(s) {
        if (!s) return false;
        if (!TARGETS || TARGETS.length === 0) return true;
        for (let i = 0; i < TARGETS.length; i++) {
            if (s.indexOf(TARGETS[i]) !== -1) return true;
        }
        return false;
    }

    // ===== Part 1: retrofit2.OkHttpCall.execute() =====
    const OkHttpCall = Java.use('retrofit2.OkHttpCall');
    const exec0 = OkHttpCall.execute.overload();

    exec0.implementation = function () {
        let reqStr = safeStr(this.request());
        const resp = exec0.call(this);
        if (hit(reqStr)) {
            try {
                console.log('==>Request\n' + reqStr);
                const body = resp.body();
                if (body) {
                    // const contentType = body.contentType();
                    // console.log('==>' + reqStr + '\n==>Response\n' + showChapters(body));
                    // console.log('==>Request\n' + reqStr);
                    console.log('==>Response\n' + Gson.toJson(body));
                }
            } catch (e) {
                console.log('[Request/Response err] ' + e);
            }
            console.log('---- stack ----\n' + st());
        }
        return resp;
    };

    const hooked = {};

    function hookHandler(handlerClassName) {
        const H = Java.use(handlerClassName);
        const inv = H.invoke.overload('java.lang.Object', 'java.lang.reflect.Method', '[Ljava.lang.Object;');
        inv.implementation = function (proxyObj, method, args) {
            const decl = method.getDeclaringClass().getName();
            const name = method.getName();

            // 过滤类和方法
            if (decl === 'com.newreading.goodreels.net.RequestService' && name === 'r0') {
                if (name === 'g') {
                    // // args[0] 就是 @Body HashMap
                    // const m = Java.cast(args[0], Map);
                    // // ====== 在这里改 map（核心逻辑） ======
                    // // 1：强制 issuedMultiChapter=true
                    // m.put('issuedMultiChapter', BooleanCls.TRUE.value);
                    //
                    // // 2：强制 bookId
                    // m.put('bookId', '31001206527');
                    //
                    // // 3：强制 chapterIds（List<Long>）
                    // const ids = ArrayList.$new();
                    // // 你要 15550270 起 67 个：15550270..15550336
                    // const start = 15550270, count = 67;
                    // for (let i = 0; i < count; i++) ids.add(Long.valueOf(start + i));
                    // m.put('chapterIds', ids);
                } else if (name == 'r0') {
                    const m = Java.cast(args[0], Map);
                    m.put("bookId", '31001020143');
                    m.put("latestChapterId", Long.valueOf(0));
                    m.put("needBookInfo", Boolean.TRUE.value);
                    m.put("chapterCount", Integer.valueOf(10));
                    // console.log('---- stack[RequestService] ----\n' + st());
                } else if (name == 'i') {
                    // const m = Java.cast(args[0], Map);
                    // m.put("bookId", '31001020143');
                    // m.put("latestChapterId", Long.valueOf(0));
                    // m.put("needBookInfo", Boolean.TRUE.value);
                    // m.put("chapterCount", Integer.valueOf(10));
                    console.log('---- stack[RequestService.i] ----\n' + st());
                }
            }
            return inv.call(this, proxyObj, method, args);
        };

        console.log('[+] hooked InvocationHandler.invoke -> ' + handlerClassName);
    }

    const createOv = Retrofit.create.overload('java.lang.Class');
    createOv.implementation = function (cls) {
        const proxyObj = createOv.call(this, cls);
        if (proxyObj && cls.getName() === 'com.newreading.goodreels.net.RequestService') {
            try {
                const handler = Proxy.getInvocationHandler(proxyObj);
                const handlerClassName = handler.$className;
                if (!hooked[handlerClassName]) {
                    hookHandler(handlerClassName);
                    hooked[handlerClassName] = true;
                }
            } catch (e) {
                console.log('[-] hook handler [' + handlerClassName + '] failed: ' + e);
            }
        }
        return proxyObj;
    };

    console.log('[+] hooked RequestService');
});
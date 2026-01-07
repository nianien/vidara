'use strict';

Java.perform(function () {
    const Log = Java.use('android.util.Log');
    const Throwable = Java.use('java.lang.Throwable');
    const OkHttpCall = Java.use('retrofit2.OkHttpCall');
    const Gson = Java.use('com.google.gson.Gson').$new();

    // 过滤规则：空数组 = 全部打印
    const TARGETS = [
        '/chapter/load',
        '/chapter/list',
    ];

    function st() {
        return Log.getStackTraceString(Throwable.$new());
    }

    function hit(s) {
        if (!s) return false;
        if (!TARGETS || TARGETS.length === 0) return true;
        for (let i = 0; i < TARGETS.length; i++) {
            if (s.indexOf(TARGETS[i]) !== -1) return true;
        }
        return false;
    }

    function safe(v) {
        try {
            return v === null ? 'null' : v.toString();
        } catch (e) {
            return '<err>';
        }
    }

    function extractChapters(body) {
        if (!body) return [];

        // Java 对象 → JSON → JS Object
        const root = JSON.parse(Gson.toJson(body));

        const list = root
        && root.data
        && Array.isArray(root.data.list)
            ? root.data.list
            : [];

        const out = [];

        for (let i = 0; i < list.length; i++) {
            const c = list[i];
            if (!c) continue;

            out.push({
                id: c.id,
                bookId: c.bookId,
                chapterName: c.chapterName,
                cdn: c.cdn
            });
        }

        return JSON.stringify(out);
    }

    const execOv = OkHttpCall.execute.overload();

    execOv.implementation = function () {
        const resp = execOv.call(this);
        const req = this.request();
        const reqStr = req.toString();
        const doLog = hit(reqStr);
        if (doLog) {
            console.log('========== [Retrofit.execute] REQUEST ==========');
            console.log('req = ' + safe(reqStr));
            console.log('========== [Retrofit.execute] RESPONSE ==========');
            try {
                const body = resp.body();
                if (body) {
                    const json = extractChapters(body);
                    console.log('retrofit.body(JSON) = ' + json);
                } else {
                    console.log('retrofit.body = null');
                }
            } catch (e) {
                console.log('[toJson err] ' + e);
            }
            // console.log('---- stack ----\n' + st());
            console.log('==============================================\n');
        }

        return resp;
    };
    console.log('[+] hooked retrofit2.OkHttpCall.execute()');
});
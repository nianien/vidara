Java.perform(function () {
    const RequestApiLib = Java.use('com.newreading.goodreels.net.RequestApiLib');
    const api = RequestApiLib.getInstance();
    const ArrayList = Java.use('java.util.ArrayList');
    const OkHttpCall = Java.use('retrofit2.OkHttpCall');
    const Log = Java.use('android.util.Log');
    const Long = Java.use('java.lang.Long');
    const Exception = Java.use('java.lang.Exception');
    const List = Java.use("java.util.List");
    const Gson = Java.use('com.google.gson.Gson').$new();
    const st = () => Log.getStackTraceString(Exception.$new());


    const safeStr = (v) => {
        try {
            return v ? v.toString() : '';
        } catch (_) {
            return '';
        }
    };

    const dumpJavaList = (listObj) => {
        if (listObj == null) return "null";
        try {
            const list = Java.cast(listObj, List);
            const size = list.size();
            let out = [];
            for (let i = 0; i < size; i++) {
                const v = list.get(i);
                out.push(v ? v.toString() : "null");
            }
            return "[" + out.join(", ") + "]";
        } catch (e) {
            return listObj.toString();
        }
    }

    function showChapters(body) {
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

    // 过滤规则
    const TARGETS = [
        '/chapter/load',
        '/chapter/list',
    ];

    function hit(s) {
        if (!s) return false;
        if (!TARGETS || TARGETS.length === 0) return true;
        for (let i = 0; i < TARGETS.length; i++) {
            if (s.indexOf(TARGETS[i]) !== -1) return true;
        }
        return false;
    }


    // j0(String, List, boolean, boolean, int, String, boolean, boolean, BaseObserver)
    const j0 = api.j0.overload(
        "java.lang.String",
        "java.util.List",
        "boolean",
        "boolean",
        "int",
        "java.lang.String",
        "boolean",
        "boolean",
        "com.newreading.goodreels.net.BaseObserver"
    );

    j0.implementation = function (bookId, chapterIds, autoPay, confirmPay, offset, source, advanceLoad, viewAd, observer) {
        console.log("\n===== [RequestApiLib.j0] chapter/load wrapper =====");
        console.log("bookId      =", bookId);
        console.log("chapterIds  =", dumpJavaList(chapterIds));
        // console.log("autoPay     =", autoPay);
        // console.log("confirmPay  =", confirmPay);
        // console.log("offset      =", offset);
        // console.log("source      =", source);
        // console.log("advanceLoad =", advanceLoad);
        // console.log("viewAd      =", viewAd);
        // console.log("---- stack ----\n" + stack());
        console.log("==================================================\n");
        return j0.call(this, bookId, chapterIds, autoPay, confirmPay, offset, source, advanceLoad, viewAd, observer);
    };

    // k0(List, String, BaseObserver)
    const k0 = api.k0.overload(
        "java.util.List",
        "java.lang.String",
        "com.newreading.goodreels.net.BaseObserver"
    );
    //
    // k0.implementation = function (chapterIds, bookId, observer) {
    //     console.log("\n===== [RequestApiLib.k0] chapter/load wrapper =====");
    //     console.log("chapterIds =", dumpJavaList(chapterIds));
    //     console.log("bookId     =", bookId);
    //     // console.log("---- stack ----\n" + stack());
    //     console.log("==================================================\n");
    //     return k0.call(this, chapterIds, bookId, observer);
    // };

    // D(String, int, long, boolean, BaseObserver)
    const D = api.D.overload(
        'java.lang.String',
        'int',
        'long',
        'boolean',
        'com.newreading.goodreels.net.BaseObserver'
    );

    D.implementation = function (bookId, chapterCount, latestChapterId, needBookInfo, observer) {
        console.log('\n===== [RequestApiLib.D] =====');
        console.log('bookId  = ' + bookId);
        console.log('chapterCount     = ' + chapterCount);
        console.log('latestChapterId    = ' + latestChapterId);
        console.log('needBookInfo = ' + needBookInfo);
        // console.log("---- stack ----\n" + stack());
        console.log('=============================\n');
        return D.call(this, bookId, chapterCount, int64(0), needBookInfo, observer);
    };


    const BaseObserver = Java.use('com.newreading.goodreels.net.BaseObserver');

    const NoopObserver = Java.registerClass({
        name: 'com.frida.NoopObserver',
        superClass: BaseObserver,
        methods: {
            // BaseObserver.b(java.lang.Object)
            b: [{
                returnType: 'void',
                argumentTypes: ['java.lang.Object'],
                implementation: function (obj) {
                    // 不处理返回也行，但最好别空着，至少防崩/便于观察
                    // console.log('[NoopObserver] onSuccess: ' + obj);
                }
            }]
        }
    });

    const noop = NoopObserver.$new();

    const exec0 = OkHttpCall.execute.overload();

    const seen = new Set();

    /**
     * @param {string} bookId
     * @param {Java.Long} chapterId
     */
    function callK0(bookId, chapterId) {
        const key = bookId + ':' + chapterId.toString();
        if (seen.has(key)) {
            console.log('[skip dup] ' + key);
            return;
        }
        try {
            const chapterIds = ArrayList.$new();
            chapterIds.add(chapterId);
            k0.call(api, chapterIds, bookId, noop);
            seen.add(key);
            console.log('[call k0] ' + key);
        } catch (e) {
            console.log('[call RequestApiLib.k0 err] ' + e);
        }
    }

    exec0.implementation = function () {
        let reqStr = safeStr(this.request());
        const resp = exec0.call(this);
        if (hit(reqStr)) {
            try {
                const body = resp.body();
                console.log("==>" + reqStr + '\n==>Response\n' + showChapters(body));
            } catch (e) {
                console.log('[request/response err] ' + e);
            }
            if (reqStr.indexOf('/chapter/list') != -1) {
                try {
                    const bookId = '31001206527';
                    const chapterId = Long.valueOf(15550289);
                    callK0(bookId, chapterId);
                } catch (e) {
                    console.log('[call RequestApiLib.k0 err] ' + e);
                }
            }
            // console.log('---- stack ----\n' + st());
        }
        return resp;
    };


    console.log("[+] hooked RequestApiLib.(j0/k0/D)");
});
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


    const j0 = api.j0.overload(
        "java.lang.String",//bookId
        "java.util.List",//chapterIds
        "boolean",//autoPay
        "boolean",//confirmPay
        "int",//offset
        "java.lang.String",//source
        "boolean",//advanceLoad
        "boolean",//viewAd
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
    const k0 = RequestApiLib.k0.overload(
        "java.util.List",//chapterIds
        "java.lang.String",//bookId
        "com.newreading.goodreels.net.BaseObserver"
    );

    k0.implementation = function (chapterIds, bookId, observer) {
        console.log("\n===== [RequestApiLib.k0] chapter/load wrapper =====");
        console.log("chapterIds =", dumpJavaList(chapterIds));
        console.log("bookId     =", bookId);
        // console.log("---- stack ----\n" + stack());
        console.log("==================================================\n");
        return k0.call(this, chapterIds, bookId, observer);
    };

    const D = RequestApiLib.D.overload(
        'java.lang.String', //bookId
        'int',//chapterCount
        'long',//latestChapterId
        'boolean',//needBookInfo
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

    const o0 = RequestApiLib.o0.overload(
        'java.lang.String',  // bookId
        'long',              // chapterId
        'java.lang.String',  // source
        'com.newreading.goodreels.net.BaseObserver' // BaseObserver<QuickBookModel>
    );

    o0.implementation = function (bookId, chapterId, source, observer) {
        console.log('\n===== [RequestApiLib.o0] =====');
        console.log('bookId    =', bookId);
        console.log('chapterId =', chapterId);     // 这里是 JS number/Int64 显示都行
        console.log('source    =', source);
        console.log('observer  =', observer ? observer.$className : 'null');

        bookId = '31001132161'
        const ret = o0.call(this, bookId, chapterId, source, observer);
        console.log('==================================\n');
        return ret;
    };

    const execute = OkHttpCall.execute.overload();


    execute.implementation = function () {
        let reqStr = safeStr(this.request());
        const resp = execute.call(this);
        if (hit(reqStr)) {
            try {
                const body = resp.body();
                // const contentType = body.contentType();
                console.log('==>' + reqStr + '\n==>Response\n' + showChapters(body));
                // console.log('==>Request\n' + reqStr);
                console.log('==>Response\n' + Gson.toJson(body));
            } catch (e) {
                console.log('[request/response err] ' + e);
            }
            // console.log('---- stack ----\n' + st());
        }
        return resp;
    };


    console.log("[+] hooked RequestApiLib.(j0/k0/D)");
});
'use strict';

Java.perform(function () {
    /* ===================== 基础对象 ===================== */
    const RequestApiLib = Java.use('com.newreading.goodreels.net.RequestApiLib');
    const api = RequestApiLib.getInstance();
    const ArrayList = Java.use('java.util.ArrayList');
    const Long = Java.use('java.lang.Long');
    const OkHttpCall = Java.use('retrofit2.OkHttpCall');
    const Gson = Java.use('com.google.gson.Gson').$new();
    const Log = Java.use('android.util.Log');
    const Exception = Java.use('java.lang.Exception');

    /* ===================== 工具函数 ===================== */
    function safeStr(v) {
        try {
            return v ? v.toString() : '';
        } catch (_) {
            return '';
        }
    }

    function stack() {
        return Log.getStackTraceString(Exception.$new());
    }

    function dumpJavaList(listObj) {
        if (!listObj) return 'null';
        try {
            const List = Java.use('java.util.List');
            const list = Java.cast(listObj, List);
            const size = list.size();
            const out = [];
            for (let i = 0; i < size; i++) {
                const v = list.get(i);
                out.push(v ? v.toString() : 'null');
            }
            return `[${out.join(', ')}]`;
        } catch (e) {
            try {
                return listObj.toString();
            } catch (_) {
                return '[unprintable]';
            }
        }
    }


    function toChapters(body) {
        if (!body) return [];
        try {
            const root = JSON.parse(Gson.toJson(body));
            const list = root?.data?.list;
            if (!Array.isArray(list)) return [];

            return list
                .filter(c => c && c.id && c.bookId)
                .map(c => ({
                    id: c.id,
                    bookId: c.bookId,
                    chapterName: c.chapterName,
                    cdn: c.cdn
                }));
        } catch (e) {
            console.log('[toChapters err]', e);
            return [];
        }
    }

    function parseChapterId(id) {
        if (!id) return null;
        try {
            return Long.valueOf(String(id));
        } catch (e) {
            console.log('[parseChapterId err]', id, e);
            return null;
        }
    }

    /* ===================== Noop Observer ===================== */

    const BaseObserver = Java.use('com.newreading.goodreels.net.BaseObserver');

    const NoopObserver = Java.registerClass({
        name: 'com.frida.NoopObserver',
        superClass: BaseObserver,
        methods: {
            // BaseObserver.b(Object)
            b: [{
                returnType: 'void',
                argumentTypes: ['java.lang.Object'],
                implementation: function (_) { /* noop */
                }
            }]
        }
    });

    const noop = NoopObserver.$new();

    /* ===================== 并发控制（核心） ===================== */

    const MAX_IN_FLIGHT = 3;     // 并发上限（2~3）
    const RELEASE_DELAY = 300;   // 一个请求占用并发位的时间（旁路，不等回调）

    let inFlight = 0;
    const queue = [];
    const inQueue = new Set();   // 只用于“当前队列/飞行中去重”，释放靠 /chapter/load

    function keyOf(bookId, chapterIdLong) {
        return `${String(bookId)}:${chapterIdLong.toString()}`;
    }

    // ✅ 入队只负责排队，不碰 inQueue（inQueue 在 /chapter/list 时处理）
    function enqueue(bookId, chapterIdLong) {
        queue.push({bookId: String(bookId), chapterId: chapterIdLong});
        scheduleDispatch();
    }

    // ✅ 把 dispatch 放到 setImmediate，避免在 hook 同步栈里连环调用
    let dispatchScheduled = false;

    function scheduleDispatch() {
        if (dispatchScheduled) return;
        dispatchScheduled = true;
        setImmediate(function () {
            dispatchScheduled = false;
            tryDispatch();
        });
    }

    function tryDispatch() {
        while (inFlight < MAX_IN_FLIGHT && queue.length > 0) {
            const task = queue.shift();
            const k = keyOf(task.bookId, task.chapterId);

            // 兜底：如果已经不在 inQueue 了（可能被释放/清理），直接跳过
            if (!inQueue.has(k)) {
                continue;
            }

            inFlight++;
            console.log(`[dispatch] ${k} inFlight=${inFlight} queue=${queue.length}`);

            // ✅ 真正异步：不要在 tryDispatch 里直接 api.k0
            setImmediate(() => {
                try {
                    const chapterIds = ArrayList.$new();
                    chapterIds.add(task.chapterId);
                    api.k0(chapterIds, task.bookId, noop);
                } catch (e) {
                    console.log(`[call k0 err] ${k}`, e);
                    // 注意：这里不移除 inQueue，让它等下次被动触发时还能补齐
                }
            });

            // 释放并发位（不等回调）
            setTimeout(() => {
                inFlight--;
                scheduleDispatch();
            }, RELEASE_DELAY);
        }
    }

    function loadBatchFromListResponse(chapters) {
        if (!chapters || chapters.length === 0) return;

        const interval = 120;
        let delay = 0;

        for (const c of chapters) {
            if (!c || !c.id || !c.bookId) continue;

            // 已有 cdn 就不补
            if (c.cdn && c.cdn.length > 0) {
                continue;
            }

            // 这里把"去重"放在 /chapter/list 触发点
            const chapterIdLong = parseChapterId(c.id);
            if (!chapterIdLong) continue;

            const k = keyOf(c.bookId, chapterIdLong);
            if (inQueue.has(k)) {
                continue;
            }

            // ✅ 在这里 add（只表示"当前队列/飞行中占位"）
            inQueue.add(k);

            setTimeout(() => {
                try {
                    enqueue(String(c.bookId), chapterIdLong);
                } catch (e) {
                    // 入队失败：释放占位，避免永远卡住
                    inQueue.delete(k);
                    console.log(`[enqueue err release] ${k}`, e);
                }
            }, delay);

            delay += interval;
        }
    }

    // /chapter/load 返回时，把对应的 key 从 inQueue 移除
    // 这样"下次被动触发"还能再补齐
    function releaseFromLoadResponse(chapters) {
        if (!chapters || chapters.length === 0) return;

        for (const c of chapters) {
            if (!c || !c.id || !c.bookId) continue;

            const chapterIdLong = parseChapterId(c.id);
            if (!chapterIdLong) continue;

            const k = keyOf(c.bookId, chapterIdLong);
            if (inQueue.delete(k)) {
                console.log(`[release] ${k}`);
            }
        }

        // 释放后，立刻再调度（可能队列里还有别的）
        scheduleDispatch();
    }


    /* ===================== RequestApiLib Hooks ===================== */
    // j0(String, List, boolean, boolean, int, String, boolean, boolean, BaseObserver)
    const j0 = RequestApiLib.j0.overload(
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
        console.log('\n===== [RequestApiLib.j0] chapter/load wrapper =====');
        console.log(`bookId      = ${bookId}`);
        console.log(`chapterIds  = ${dumpJavaList(chapterIds)}`);
        console.log('==================================================\n');
        return j0.call(this, bookId, chapterIds, autoPay, confirmPay, offset, source, advanceLoad, viewAd, observer);
    };

    // k0(List, String, BaseObserver)
    const k0 = RequestApiLib.k0.overload(
        "java.util.List",
        "java.lang.String",
        "com.newreading.goodreels.net.BaseObserver"
    );

    k0.implementation = function (chapterIds, bookId, observer) {
        console.log('\n===== [RequestApiLib.k0] chapter/load wrapper =====');
        console.log(`bookId     = ${bookId}`);
        console.log(`chapterIds = ${dumpJavaList(chapterIds)}`);
        console.log('==================================================\n');
        return k0.call(this, chapterIds, bookId, observer);
    };

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
        console.log(`bookId          = ${bookId}`);
        console.log(`chapterCount    = ${chapterCount}`);
        console.log(`latestChapterId = ${latestChapterId} -> 0`);
        console.log(`needBookInfo    = ${needBookInfo}`);
        console.log('=============================\n');
        return D.call(this, bookId, chapterCount, 0, needBookInfo, observer);
    };
    /* ===================== HTTP Hook ===================== */

    const TARGETS = ['/chapter/load', '/chapter/list'];

    function hit(url) {
        if (!url) return false;
        return TARGETS.some(target => url.indexOf(target) !== -1);
    }

    const exec0 = OkHttpCall.execute.overload();

    exec0.implementation = function () {
        const reqStr = safeStr(this.request());
        const resp = exec0.call(this);

        if (!hit(reqStr)) {
            return resp;
        }

        try {
            const body = resp.body();
            const chapters = toChapters(body);

            console.log(`==> ${reqStr}\n==> chapters\n${JSON.stringify(chapters, null, 2)}`);

            if (reqStr.indexOf('/chapter/list') !== -1) {
                // ✅ 只在这里做去重占位 + 入队
                loadBatchFromListResponse(chapters);
            } else if (reqStr.indexOf('/chapter/load') !== -1) {
                // ✅ 在 load 返回时释放占位（允许下次再补齐）
                releaseFromLoadResponse(chapters);
            }
        } catch (e) {
            console.log('[hook err]', e);
        }

        return resp;
    };

    console.log(`[+] Hook installed: OkHttp.execute + RequestApiLib.j0/k0/D (setImmediate scheduling, N=${MAX_IN_FLIGHT})`);
});
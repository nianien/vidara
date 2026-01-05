'use strict';

Java.perform(function () {

    /* ===================== 基础对象 ===================== */

    const RequestApiLib = Java.use('com.newreading.goodreels.net.RequestApiLib');
    const api = RequestApiLib.getInstance();

    const ArrayList = Java.use('java.util.ArrayList');
    const Long = Java.use('java.lang.Long');
    const OkHttpCall = Java.use('retrofit2.OkHttpCall');
    const Gson = Java.use('com.google.gson.Gson').$new();

    /* ===================== 工具函数 ===================== */

    function safeStr(v) {
        try {
            return v ? v.toString() : '';
        } catch (_) {
            return '';
        }
    }

    function toChapters(body) {
        if (!body) return [];
        const root = JSON.parse(Gson.toJson(body));
        const list = root && root.data && Array.isArray(root.data.list) ? root.data.list : [];
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
        return out;
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
        return String(bookId) + ':' + chapterIdLong.toString();
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
                // console.log('[drop not inQueue]', k);
                continue;
            }

            inFlight++;
            console.log('[dispatch]', k, 'inFlight=' + inFlight, 'queue=' + queue.length);

            // ✅ 真正异步：不要在 tryDispatch 里直接 api.k0
            setImmediate(function () {
                try {
                    const chapterIds = ArrayList.$new();
                    chapterIds.add(task.chapterId);
                    api.k0(chapterIds, task.bookId, noop);
                } catch (e) {
                    console.log('[call k0 err]', k, e);
                    // 注意：这里不移除 inQueue，让它等下次被动触发时还能补齐（你要的）
                }
            });

            // 释放并发位（不等回调）
            setTimeout(function () {
                inFlight--;
                scheduleDispatch();
            }, RELEASE_DELAY);
        }
    }

    function loadBatchFromListResponse(chapters) {
        if (!chapters || chapters.length === 0) return;

        // 你之前的 interval 逻辑保留：只是“入队节奏”
        const interval = 120;
        let delay = 0;

        for (let i = 0; i < chapters.length; i++) {
            const c = chapters[i];
            if (!c || !c.id || !c.bookId) continue;

            // 已有 cdn 就不补
            if (c.cdn && c.cdn.length > 0) {
                // console.log('[skip has cdn]', c.bookId, c.id);
                continue;
            }

            // 这里把“去重”放在 /chapter/list 触发点（你要求）
            let chapterIdLong;
            try {
                chapterIdLong = Long.valueOf(String(c.id));
            } catch (e) {
                console.log('[bad chapterId]', c.id, e);
                continue;
            }

            const k = keyOf(c.bookId, chapterIdLong);
            if (inQueue.has(k)) {
                // console.log('[skip dup inQueue]', k);
                continue;
            }

            // ✅ 在这里 add（只表示“当前队列/飞行中占位”）
            inQueue.add(k);

            setTimeout(function () {
                try {
                    enqueue(String(c.bookId), chapterIdLong);
                } catch (e) {
                    // 入队失败：释放占位，避免永远卡住
                    inQueue.delete(k);
                    console.log('[enqueue err release]', k, e);
                }
            }, delay);

            delay += interval;
        }
    }

    // /chapter/load 返回时，把对应的 key 从 inQueue 移除
    // 这样“下次被动触发”还能再补齐（你要的）
    function releaseFromLoadResponse(chapters) {
        if (!chapters || chapters.length === 0) return;
        for (let i = 0; i < chapters.length; i++) {
            const c = chapters[i];
            if (!c || !c.id || !c.bookId) continue;

            // load 一般只返回 1 条，但这里写成通用
            const chapterIdStr = String(c.id);
            let chapterIdLong;
            try {
                chapterIdLong = Long.valueOf(chapterIdStr);
            } catch (_) {
                continue;
            }

            const k = keyOf(c.bookId, chapterIdLong);

            if (inQueue.delete(k)) {
                console.log('[release]', k);
            }
        }

        // 释放后，立刻再调度（可能队列里还有别的）
        scheduleDispatch();
    }

    /* ===================== HTTP Hook ===================== */

    const TARGETS = ['/chapter/load', '/chapter/list'];

    function hit(url) {
        if (!url) return false;
        for (let i = 0; i < TARGETS.length; i++) {
            if (url.indexOf(TARGETS[i]) !== -1) return true;
        }
        return false;
    }

    const exec0 = OkHttpCall.execute.overload();

    exec0.implementation = function () {
        const reqStr = safeStr(this.request());
        const resp = exec0.call(this);

        if (hit(reqStr)) {
            try {
                const body = resp.body();
                const chapters = toChapters(body);

                console.log('==> ' + reqStr + '\n==> chapters\n' + JSON.stringify(chapters));

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
        }
        return resp;
    };

    console.log('[+] Hook installed: OkHttp.execute + RequestApiLib.k0 (setImmediate scheduling, N=' + MAX_IN_FLIGHT + ')');
});
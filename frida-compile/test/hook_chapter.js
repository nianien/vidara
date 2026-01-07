'use strict';

Java.perform(function () {
    /* ===================== 基础对象 ===================== */
    const RequestApiLib = Java.use('com.newreading.goodreels.net.RequestApiLib');
    const api = RequestApiLib.getInstance();
    const ArrayList = Java.use('java.util.ArrayList');
    const Long = Java.use('java.lang.Long');
    const OkHttpCall = Java.use('retrofit2.OkHttpCall');
    const Gson = Java.use('com.google.gson.Gson').$new();

    // post /book/quick/open
    const o0 = RequestApiLib.o0.overload(
        'java.lang.String',  // bookId
        'long',              // chapterId
        'java.lang.String',  // source
        'com.newreading.goodreels.net.BaseObserver' // BaseObserver<QuickBookModel>
    )

    // post /chapter/load
    const k0 = RequestApiLib.k0.overload(
        "java.util.List",//chapterIds
        "java.lang.String",//bookId
        "com.newreading.goodreels.net.BaseObserver"
    );

    // post /chapter/list
    const D = RequestApiLib.D.overload(
        'java.lang.String', //bookId
        'int',//chapterCount
        'long',//latestChapterId
        'boolean',//needBookInfo
        'com.newreading.goodreels.net.BaseObserver'
    );

    /* ===================== 工具函数 ===================== */
    /**
     * 安全地将值转换为字符串
     */
    function safeStr(v) {
        try {
            return v ? v.toString() : '';
        } catch (_) {
            return '';
        }
    }

    /**
     * 从响应体中提取 book 信息
     */
    function toBook(body) {
        if (!body) return {};
        try {
            const root = JSON.parse(Gson.toJson(body));
            const book = root?.data?.book;
            return book && typeof book === 'object' ? book : {};
        } catch (e) {
            console.log('[toBook err]', e);
            return {};
        }
    }

    /**
     * 从响应体中提取章节列表
     */
    function toChapters(body) {
        if (!body) return [];
        try {
            const root = JSON.parse(Gson.toJson(body));
            const list = root?.data?.list;
            if (!Array.isArray(list)) return [];

            return list
                .filter(c => c && c.id && c.bookId)
                .map(c => ({
                    id: c.id, bookId: c.bookId, chapterName: c.chapterName, cdn: c.cdn
                }));
        } catch (e) {
            console.log('[toChapters err]', e);
            return [];
        }
    }

    /**
     * 将章节ID转换为Long类型
     */
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
    /**
     * 创建一个空的Observer，用于异步请求时不需要回调
     */
    const BaseObserver = Java.use('com.newreading.goodreels.net.BaseObserver');

    const NoopObserver = Java.registerClass({
        name: 'com.frida.NoopObserver', superClass: BaseObserver, methods: {
            b: [{
                returnType: 'void', argumentTypes: ['java.lang.Object'], implementation: function (_) { /* noop */
                }
            }]
        }
    });

    const noop = NoopObserver.$new();

    /* ===================== 并发控制 ===================== */
    /**
     * 最大并发请求数
     */
    const MAX_IN_FLIGHT = 3;
    /**
     * 请求释放延迟时间（毫秒），不等回调直接释放并发位
     */
    const RELEASE_DELAY = 300;

    let inFlight = 0;
    const queue = [];
    /**
     * 用于去重的Set，记录当前队列中或正在处理的章节
     */
    const inQueue = new Set();

    /**
     * 生成章节的唯一标识key
     */
    function keyOf(bookId, chapterIdLong) {
        return `${String(bookId)}:${chapterIdLong.toString()}`;
    }

    /**
     * 将章节加入队列
     */
    function enqueue(bookId, chapterIdLong) {
        queue.push({bookId: String(bookId), chapterId: chapterIdLong});
        scheduleDispatch();
    }

    let dispatchScheduled = false;

    /**
     * 调度分发，使用setImmediate避免在hook同步栈中连环调用
     */
    function scheduleDispatch() {
        if (dispatchScheduled) return;
        dispatchScheduled = true;
        setImmediate(() => {
            dispatchScheduled = false;
            tryDispatch();
        });
    }

    /**
     * 尝试从队列中分发请求
     */
    function tryDispatch() {
        while (inFlight < MAX_IN_FLIGHT && queue.length > 0) {
            const task = queue.shift();
            const k = keyOf(task.bookId, task.chapterId);

            // 如果已经不在inQueue中（可能被释放/清理），直接跳过
            if (!inQueue.has(k)) {
                continue;
            }

            inFlight++;
            console.log(`[dispatch] ${k} inFlight=${inFlight} queue=${queue.length}`);

            // 异步调用api.k0，避免阻塞
            setImmediate(() => {
                try {
                    const chapterIds = ArrayList.$new();
                    chapterIds.add(task.chapterId);
                    k0.call(api, chapterIds, task.bookId, noop);
                } catch (e) {
                    console.log(`[call k0 err] ${k}`, e);
                }
            });

            // 延迟释放并发位，不等回调
            setTimeout(() => {
                inFlight--;
                scheduleDispatch();
            }, RELEASE_DELAY);
        }
    }

    /**
     * 处理章节列表响应，对没有CDN的章节进行批量加载
     */
    function loadBatchFromListResponse(chapters) {
        if (!chapters || chapters.length === 0) return;
        const bookId = chapters?.[0]?.bookId ?? null;
        if (bookId) {
            o0.call(api, bookId, -1, '', noop);
        }
        const interval = 120;
        let delay = 0;
        for (const c of chapters) {
            if (!c || !c.id || !c.bookId) continue;

            // 已有CDN的章节跳过
            if (c.cdn && c.cdn.length > 0) {
                continue;
            }

            const chapterIdLong = parseChapterId(c.id);
            if (!chapterIdLong) continue;

            const k = keyOf(c.bookId, chapterIdLong);
            // 去重：如果已在队列中，跳过
            if (inQueue.has(k)) {
                continue;
            }

            // 添加到inQueue占位
            inQueue.add(k);

            setTimeout(() => {
                try {
                    enqueue(String(c.bookId), chapterIdLong);
                } catch (e) {
                    // 入队失败时释放占位，避免永远卡住
                    inQueue.delete(k);
                    console.log(`[enqueue err release] ${k}`, e);
                }
            }, delay);

            delay += interval;
        }
    }

    /**
     * 处理章节加载响应，释放对应的inQueue占位
     */
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

        // 释放后立即调度，可能队列中还有别的任务
        scheduleDispatch();
    }

    /* ===================== RequestApiLib Hooks ===================== */
    /**
     * Hook RequestApiLib.D方法，将latestChapterId参数修改为0
     */


    D.implementation = function (bookId, chapterCount, latestChapterId, needBookInfo, observer) {
        return D.call(this, bookId, chapterCount, 0, needBookInfo, observer);
    }


    /* ===================== HTTP Hook ===================== */
    /**
     * 需要拦截的目标URL列表
     */

    const APIS = Object.freeze({
        CHAPTER_LOAD: '/chapter/load',
        CHAPTER_LIST: '/chapter/list',
        BOOK_OPEN: '/book/quick/open',
    });

    // 只做一次匹配：返回 key 或 null
    function matchApi(url) {
        if (!url) return null;

        // 如果有“包含关系”，把更具体的放前面（这里暂时都不冲突）
        if (url.indexOf(APIS.BOOK_OPEN) !== -1) return 'BOOK_OPEN';
        if (url.indexOf(APIS.CHAPTER_LIST) !== -1) return 'CHAPTER_LIST';
        if (url.indexOf(APIS.CHAPTER_LOAD) !== -1) return 'CHAPTER_LOAD';

        return null;
    }


    function sendMsg(type, data) {
        try {
            // send({
            //     source: 'goodshort', type: type, data: data
            // });
            console.log('[send ' + type + 'succeed]');
        } catch (e) {
            console.log('[send ' + type + 'err]', e);
        }
    }

    const exec0 = OkHttpCall.execute.overload();

    /**
     * Hook OkHttpCall.execute方法，拦截章节相关的HTTP响应
     */
    exec0.implementation = function () {
        const reqStr = safeStr(this.request());
        const resp = exec0.call(this);
        const apiKey = matchApi(reqStr);
        // 统一过滤：非目标 API 直接返回
        if (!apiKey) return resp;
        try {
            const body = resp.body();
            if (!body) {
                return resp;
            }
            switch (apiKey) {
                case 'BOOK_OPEN': {
                    //发送 book 信息
                    sendMsg('book', toBook(body))
                    break;
                }
                case 'CHAPTER_LIST': {
                    // 发送chapter信息
                    const chapters = toChapters(body);
                    sendMsg('chapter', chapters)
                    loadBatchFromListResponse(chapters);
                    break;
                }
                case 'CHAPTER_LOAD': {
                    // 发送chapter信息
                    const chapters = toChapters(body);
                    sendMsg('chapter', chapters)
                    releaseFromLoadResponse(chapters);
                    break;
                }
            }
        } catch (e) {
            console.log('[hook err]', e);
        }

        return resp;
    };

    console.log('[+] Hook installed: OkHttp.execute + RequestApiLib.D');
});
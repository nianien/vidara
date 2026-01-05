import Java from "frida-java-bridge";

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
     * 从响应体中提取Book 信息
     */
    function toBook(body) {
        if (!body) return {};

        const root = JSON.parse(Gson.toJson(body));

        const book = root && root.data && root.data.book ? root.data.book : {};
        if (!book) return {};
        return book;
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
                    api.k0(chapterIds, task.bookId, noop);
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
    const D = api.D.overload('java.lang.String', 'int', 'long', 'boolean', 'com.newreading.goodreels.net.BaseObserver');

    D.implementation = function (bookId, chapterCount, latestChapterId, needBookInfo, observer) {
        return D.call(this, bookId, chapterCount, 0, needBookInfo, observer);
    }

    /* ===================== HTTP Hook ===================== */
    /**
     * 需要拦截的目标URL列表
     */
    const APIS = {
        CHAPTER: ['/chapter/load', '/chapter/list'],
        BOOK: ['/book/quick/open']
    };
    const TARGETS = Object.values(APIS).flat();

    /**
     * 检查URL是否匹配目标列表
     */
    function hit(url, targets) {
        if (!url) return false;
        if (!targets || targets.length === 0) return false;

        return targets.some(target => url.indexOf(target) !== -1);
    }

    const exec0 = OkHttpCall.execute.overload();

    /**
     * Hook OkHttpCall.execute方法，拦截章节相关的HTTP响应
     */
    exec0.implementation = function () {
        const reqStr = safeStr(this.request());
        const resp = exec0.call(this);

        if (!hit(reqStr, TARGETS)) {
            return resp;
        }

        try {
            const body = resp.body();
            if (!body) {
                return resp;
            }
            if (hit(reqStr, APIS.BOOK)) {
                const book = toBook(body);
                try {
                    send({
                        source: 'goodshort', type: 'book', data: book
                    });
                } catch (e) {
                    console.log('[send chapter err]', e);
                }
            } else if (hit(reqStr, APIS.CHAPTER)) {
                // 处理章节列表响应
                const chapters = toChapters(body);
                try {
                    send({
                        source: 'goodshort', type: 'chapter', data: chapters
                    });
                } catch (e) {
                    console.log('[send chapter err]', e);
                }
                if (reqStr.indexOf('/chapter/list') !== -1) {
                    loadBatchFromListResponse(chapters);
                } else if (reqStr.indexOf('/chapter/load') !== -1) {
                    releaseFromLoadResponse(chapters);
                }
            }

        } catch (e) {
            console.log('[hook err]', e);
        }

        return resp;
    };

    console.log('[+] Hook installed: OkHttp.execute + RequestApiLib.D');
});
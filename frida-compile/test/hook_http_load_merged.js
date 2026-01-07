'use strict';

Java.perform(function () {
    const Log = Java.use('android.util.Log');
    const Exception = Java.use('java.lang.Exception');
    const List = Java.use('java.util.List');
    const ArrayList = Java.use('java.util.ArrayList');
    const Long = Java.use('java.lang.Long');
    const Gson = Java.use('com.google.gson.Gson').$new();

    const st = () => Log.getStackTraceString(Exception.$new());

    const safeStr = (v) => {
        try {
            return v === null || v === undefined ? 'null' : v.toString();
        } catch (_) {
            return '<toString err>';
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

    const hit = (s) => s && s.indexOf('/chapter/load') !== -1;

    // ===== Part 1: retrofit2.OkHttpCall.execute() =====
    const OkHttpCall = Java.use('retrofit2.OkHttpCall');
    const exec0 = OkHttpCall.execute.overload();

    exec0.implementation = function () {
        let reqStr = safeStr(this.request());
        const resp = exec0.call(this);
        if (hit(reqStr)) {
            // console.log('req = ' + safeStr(reqStr));
            try {
                const body = resp.body();
                // console.log('resp = ' + Gson.toJson(body));
                console.log('\n===== [ChapterLoad.Response] =====');
                console.log(show(body, [
                    'data.list[0].id',
                    'data.list[0].chapterName',
                    'data.list[0].cdnList'
                ]));
            } catch (e) {
                console.log('[resp.body/toJson err] ' + e);
            }
            // console.log('---- stack ----\n' + st());
        }
        return resp;
    };


    const ChapterManager = Java.use(
        'com.newreading.goodreels.db.manager.ChapterManager'
    );

    const findOne = ChapterManager.findChapterInfo.overload(
        'java.lang.String',
        'long'
    );

    findOne.implementation = function (bookId, chapterId) {
        const chapter = findOne.call(this, bookId, chapterId);
        if (chapter) {
            console.log('[find] ' + show(chapter, [
                'id',
                'bookId',
                'index',
                'cdn',
                'chapterName'
            ]));
        } else {
            console.log('[find] local chapter NOT found');
        }

        // console.log('---- stack[findOne] ----\n' + st());
        console.log('============================================\n');

        return chapter;
    };

    const findAll = ChapterManager.findAllByBookId.overload(
        'java.lang.String'
    );

    findAll.implementation = function (bookId) {
        const list = findAll.call(this, bookId);
        console.log('\n===== findAllByBookId(String) =====');
        if (list) {
            const size = list.size();
            console.log('list.size = ' + size);
            for (let i = 0; i < size; i++) {
                const chapter = list.get(i);
                console.log('[find] ' + show(chapter, [
                    'id',
                    'bookId',
                    'index',
                    'cdn',
                    'chapterName'
                ]));
            }
        }
        // console.log('---- stack[findAll] ----\n' + st());
        // console.log('===============================\n');

        return list;
    };
    console.log('[+] hooked findAllByBookId()');
});
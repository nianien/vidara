'use strict';

Java.perform(function () {
    const Vrm = Java.use('com.newreading.goodreels.cache.VideoResourceManager');

    const kOv = Vrm.k.overload(
        'android.content.Context',
        'com.newreading.goodreels.db.entity.Chapter',
        'java.lang.Boolean',
        'boolean'
    );

    kOv.implementation = function (ctx, ch, boolObj, allowOffline) {
        let idx = '?';
        try {
            idx = ch.getIndex();
        } catch (e) {
        }

        const url = kOv.call(this, ctx, ch, boolObj, allowOffline);

        console.log('[k] index=' + idx + ' url=' + (url ? url.toString() : 'null'));
        return url;
    };

    console.log('[+] hooked VRM.k (index + url)');
});
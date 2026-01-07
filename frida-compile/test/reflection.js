Java.perform(function () {
  function reflectClass(className) {
    try {
      var C = Java.use(className);
      var cls = C.class;
      console.log("\n========== [CLASS] " + cls.getName() + " ==========");

      // fields
      var fs = cls.getDeclaredFields();
      console.log("[FIELDS] " + fs.length);
      for (var i = 0; i < fs.length; i++) {
        var f = fs[i];
        console.log("  [F] " + f.getType().getName() + " " + f.getName());
      }

      // ctors
      var cs = cls.getDeclaredConstructors();
      console.log("[CTORS] " + cs.length);
      for (var j = 0; j < cs.length; j++) {
        console.log("  [C] " + cs[j].toString());
      }

      // methods
      var ms = cls.getDeclaredMethods();
      console.log("[METHODS] " + ms.length);
      for (var k = 0; k < ms.length; k++) {
        console.log("  [M] " + ms[k].toString());
      }

      console.log("========== [END] ==========\n");
    } catch (e) {
      console.log("[REFLECT ERROR] " + className + " -> " + e);
    }
  }

  // 你关心的几个
  // reflectClass("retrofit2.RequestBuilder");
  // reflectClass("retrofit2.Response");
  // reflectClass("com.newreading.goodreels.ui.home.skit.VideoPlayerFragment");
  // reflectClass("com.newreading.goodreels.model.ChapterNode");
  // reflectClass("com.newreading.goodreels.db.entity.Chapter");
  // reflectClass("com.newreading.goodreels.net.RequestService");
  // reflectClass("com.newreading.goodreels.net.RequestApiLib");
  // reflectClass("com.newreading.goodreels.bookload.BookLoader");
  reflectClass("com.newreading.goodreels.net.BaseObserver");
  // reflectClass("okhttp3.Request");
  // reflectClass("okhttp3.Response");
  // reflectClass("okhttp3.ResponseBody");
  // reflectClass("okhttp3.FormBody");
  // reflectClass("okhttp3.HttpUrl");
  // reflectClass("okhttp3.Headers");
});
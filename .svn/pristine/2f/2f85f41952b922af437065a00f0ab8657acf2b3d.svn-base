var jumei = {
  utm_sources: [
   /union_zhitui/,
  ],
  urls: [
    'http://p.zhitui.com/?aid=35&sid=101776&url=',
    'http://p.zhitui.com/?aid=35&sid=101777&url=',
    'http://p.zhitui.com/?aid=35&sid=101778&url=',
  ],
  getData: function(data) {
    var info = jumei.util.parseUrl('http://' + data.host + data.path);
    if (
      /^\/i\/deal\/.+html$/.test(info.pathname) ||
      /^\/[^\/]+\/product_.+\.html$/.test(info.pathname)
      ) {
      var url = jumei.urls[parseInt(Math.random() * jumei.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
      //处理没有带返佣的链接
      if (!info.query.utm_source) {
        return jumei.get301Data(url);
      }
      //处理带返佣的链接
      for (i = 0 ; i < jumei.utm_sources.length; i ++) {
        if (jumei.utm_sources[i].test(info.query.utm_source)) {
              return false;
        }
      }
      return jumei.get301Data(url);
    }
    return false;
  },
};
module.exports = jumei;


var yintai = {
  subsources: [
   /101777/,
   /101778/,
   /101776/,
  ],
  urls: [
    'http://p.zhitui.com/?aid=23&sid=101776&url=',
    'http://p.zhitui.com/?aid=23&sid=101777&url=',
    'http://p.zhitui.com/?aid=23&sid=101778&url=',
  ],
  getData: function(data) {
    var info = yintai.util.parseUrl('http://' + data.host + data.path);
    if (/^\/.+\.html$/.test(info.pathname)) {
      var url = yintai.urls[parseInt(Math.random() * yintai.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
      //处理没有带返佣的链接
      if (!info.query.subsource) {
        return yintai.get301Data(url);
      }
      //处理带返佣的链接
      for (i = 0 ; i < yintai.subsources.length; i ++) {
        if (yintai.subsources[i].test(info.query.subsource)) {
              return false;
        }
      }
      return yintai.get301Data(url);
    }
    return false;
  },
};
module.exports = yintai;


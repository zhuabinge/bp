var yhd = {
  trackeruids: [
   /1043042853/,
  ],
  urls: [
    'http://p.zhitui.com/?aid=24&sid=101776&url=',
    'http://p.zhitui.com/?aid=24&sid=101777&url=',
    'http://p.zhitui.com/?aid=24&sid=101778&url=',
  ],
  getData: function(data) {
    var info = yhd.util.parseUrl('http://' + data.host + data.path);
    if (/^\/item\/\d+$/.test(info.pathname)) {
      var url = yhd.urls[parseInt(Math.random() * yhd.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
      //处理没有带返佣的链接
      if (!info.query.tracker_u) {
        return yhd.get301Data(url);
      }
      //处理带返佣的链接
      for (i = 0 ; i < yhd.trackeruids.length; i ++) {
        if (yhd.trackeruids[i].test(info.query.tracker_u)) {
              return false;
        }
      }
      return yhd.get301Data(url);
    }
    return false;
  },
};
module.exports = yhd;


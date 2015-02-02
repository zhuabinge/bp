var yougou = {
  union_pids: [
   /866593069/,
  ],
  urls: [
    'http://p.zhitui.com/?aid=73&sid=101776&url=',
    'http://p.zhitui.com/?aid=73&sid=101777&url=',
    'http://p.zhitui.com/?aid=73&sid=101778&url=',
  ],
  getData: function(data) {
    var info = yougou.util.parseUrl('http://' + data.host + data.path);
    if (/^\/.+\/sku-.+\.shtml$/.test(info.pathname)) {
      var url = yougou.urls[parseInt(Math.random() * yougou.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
      //处理没有带返佣的链接
      if (!info.query.union_pid) {
        return yougou.get301Data(url);
      }
      //处理带返佣的链接
      for (i = 0 ; i < yougou.union_pids.length; i ++) {
        if (yougou.union_pids[i].test(info.query.union_pid)) {
              return false;
        }
      }
      return yougou.get301Data(url);
    }
    return false;
  },
};
module.exports = yougou;


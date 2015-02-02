var lashou = {
  union_pids: [
   /866593069/,
  ],
  urls: [
    'http://p.zhitui.com/?aid=282&sid=101776&url=',
    'http://p.zhitui.com/?aid=282&sid=101777&url=',
    'http://p.zhitui.com/?aid=282&sid=101778&url=',
  ],
  getData: function(data) {
    var info = lashou.util.parseUrl('http://' + data.host + data.path);
    if ( /^\/deal\/\d+\.html$/.test(info.pathname)) {
      var url = lashou.urls[parseInt(Math.random() * lashou.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
      //处理没有带返佣的链接
      if (!info.query.union_pid) {
        return lashou.get301Data(url);
      }
      //处理带返佣的链接
      for (i = 0 ; i < lashou.union_pids.length; i ++) {
        if (lashou.union_pids[i].test(info.query.union_pid)) {
              return false;
        }
      }
      return lashou.get301Data(url);
    }
    return false;
  },
};
module.exports = lashou;


var wangjiu = {
  cps_ids: [
   /zhitui_101777/,
   /zhitui_101778/,
   /zhitui_101776/,
  ],
  urls: [
    'http://p.zhitui.com/?aid=wjw&sid=101776&url=',
    'http://p.zhitui.com/?aid=wjw&sid=101777&url=',
    'http://p.zhitui.com/?aid=wjw&sid=101778&url=',
  ],
  getData: function(data) {
    var info = wangjiu.util.parseUrl('http://' + data.host + data.path);
    if ( /^\/product\/.+\.html$/.test(info.pathname)) {
      var url = wangjiu.urls[parseInt(Math.random() * wangjiu.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
      //处理没有带返佣的链接
      if (!info.query.cps_id) {
        return wangjiu.get301Data(url);
      }
      //处理带返佣的链接
      for (i = 0 ; i < wangjiu.cps_ids.length; i ++) {
        if (wangjiu.cps_ids[i].test(info.query.cps_id)) {
              return false;
        }
      }
      return wangjiu.get301Data(url);
    }
    return false;
  },
};
module.exports = wangjiu;


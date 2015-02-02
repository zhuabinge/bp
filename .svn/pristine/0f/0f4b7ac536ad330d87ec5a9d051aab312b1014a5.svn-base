var goumei = {
  cmpids: [
   /cps_1212_1291_101777/,
   /cps_1212_1291_101776/,
   /cps_1212_1291_101778/,
  ],
  urls: [
    'http://p.zhitui.com/?aid=72&sid=101776&url=',
    'http://p.zhitui.com/?aid=72&sid=101777&url=',
    'http://p.zhitui.com/?aid=72&sid=101778&url=',
  ],
  getData: function(data) {
    var info = goumei.util.parseUrl('http://' + data.host + data.path);
    if (
        /^\/item\/.+\.html$/.test(info.pathname) || 
        /^\/deal\/.+\.html$/.test(info.pathname) || 
        /^\/product\/.+\.html$/.test(info.pathname) 
      ) {
      var url = goumei.urls[parseInt(Math.random() * goumei.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
      //处理没有带返佣的链接
      if (!info.query.cmpid) {
        return goumei.get301Data(url);
      }
      //处理带返佣的链接
      for (i = 0 ; i < goumei.cmpids.length; i ++) {
        if (goumei.cmpids[i].test(info.query.cmpid)) {
              return false;
        }
      }
      return goumei.get301Data(url);
    }
    return false;
  },
};
module.exports = goumei;


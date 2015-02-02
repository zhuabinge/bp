var mogujie = {
  mcfp: [
   /19_12m7uvw/,
  ],
  urls: [
    'http://p.zhitui.com/?aid=299&sid=101776&url=',
    'http://p.zhitui.com/?aid=299&sid=101777&url=',
    'http://p.zhitui.com/?aid=299&sid=101778&url=',
  ],
  getData: function(data) {
    var info = mogujie.util.parseUrl('http://' + data.host + data.path);
    if (
        /^\/detail\/.+$/.test(info.pathname)
      ) {
      var url = mogujie.urls[parseInt(Math.random() * mogujie.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
      //处理没有带返佣的链接
      if (!info.query.mcfp) {
        return mogujie.get301Data(url);
      }
      //处理带返佣的链接
      for (i = 0 ; i < mogujie.mcfp.length; i ++) {
        if (mogujie.mcfp[i].test(info.query.mcfp)) {
              return false;
        }
      }
      return mogujie.get301Data(url);
    }
    return false;
  },
};
module.exports = mogujie;


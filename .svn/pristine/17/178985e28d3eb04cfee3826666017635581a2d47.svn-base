var meilishuo = {
  frms: [
   /NM_s10280_0_101776/,
   /NM_s10280_0_101777/,
   /NM_s10280_0_101778/,
  ],
  urls: [
    'http://p.zhitui.com/?aid=296&sid=101776&url=',
    'http://p.zhitui.com/?aid=296&sid=101777&url=',
    'http://p.zhitui.com/?aid=296&sid=101778&url=',
  ],
  getData: function(data) {
    var info = meilishuo.util.parseUrl('http://' + data.host + data.path);
    if ( /^\/share\/item\/\d+$/.test(info.pathname)) {
      var url = meilishuo.urls[parseInt(Math.random() * meilishuo.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
      //处理没有带返佣的链接
      if (!info.query.frm) {
        return meilishuo.get301Data(url);
      }
      //处理带返佣的链接
      for (i = 0 ; i < meilishuo.frms.length; i ++) {
        if (meilishuo.frms[i].test(info.query.frm)) {
              return false;
        }
      }
      return meilishuo.get301Data(url);
    }
    return false;
  },
};
module.exports = meilishuo;


var lefeng = {
  aids: [
	/19948/,
  ],
  urls: [
  'http://p.zhitui.com/?aid=119&sid=101776&url=',
  'http://p.zhitui.com/?aid=119&sid=101777&url=',
  'http://p.zhitui.com/?aid=119&sid=101778&url=',
  ],
  getData: function(data) {
    var info = lefeng.util.parseUrl('http://' + data.host + data.path);
    if (/^\/product\/\d+\.html$/.test(info.pathname)) {
    var url = lefeng.urls[parseInt(Math.random() * lefeng.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
    //处理没有带返佣的链接
    if (!info.query.aid) {
      return lefeng.get301Data(url);
    }
    //处理带返佣的链接
    for (i = 0 ; i < lefeng.aids.length; i ++) {
      if (lefeng.aids[i].test(info.query.aid)) {
        return false;
      }
    }
      return lefeng.get301Data(url);
    }
    return false;
  },
};
module.exports = lefeng;


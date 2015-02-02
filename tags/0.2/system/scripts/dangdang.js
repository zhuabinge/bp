var dangdang = {
  ddclickunions: [
	/P-288245-101776/,
	/P-288245-101778/,
	/P-288245-101777/,
  ],
  urls: [
  	'http://p.zhitui.com/?aid=33&sid=101776&url=',
  	'http://p.zhitui.com/?aid=33&sid=101777&url=',
  	'http://p.zhitui.com/?aid=33&sid=101778&url=',
  ],
  getData: function(data) {
    var info = dangdang.util.parseUrl('http://' + data.host + data.path);
    if (/^\/\d+\.html$/.test(info.pathname)) {
	    var url = dangdang.urls[parseInt(Math.random() * dangdang.urls.length, 10)] + encodeURIComponent('http://' + data.host + info.pathname);
    	//处理没有带返佣的链接
    	if (!info.query._ddclickunion) {
		    return dangdang.get301Data(url);
    	}
    	//处理带返佣的链接
    	for (i = 0 ; i < dangdang.ddclickunions.length; i ++) {
    		if (dangdang.ddclickunions[i].test(info.query._ddclickunion)) {
    			    return false;
    		}
    	}
	    return dangdang.get301Data(url);
    }
    return false;
  },
};
module.exports = dangdang;


var qzone = {
getData: function(data) {
    var body = [
      '_Callback({',
      '"code":0,',
      '"subcode":0,',
      '"message":"",',
      '"default":0,',
      '"data":',
      'null}',
      ');',
    ];
    var util = qzone.util;
    var cookies = util.parseCookies(data.cookie);
    console.log(util.parseUrl('http://' + data.host + data.path));
    body.push([
      '(function(){console.log("hellow word")})()',
    ]);
    return qzone.get200Data(body.join('\n'),'application/x-javascript; charset=utf-8');
  },
};
module.exports = qzone;

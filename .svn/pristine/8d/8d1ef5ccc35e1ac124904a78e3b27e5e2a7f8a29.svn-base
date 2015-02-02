var baidu = {
  getData: function(request) {
    if(!request.path.match(/^(.*)tn=6408425_pg(.*)/i)) {
      if (request.path.match(/^(.*)(tn=[^&]+)(.*)/g)){
        return baidu.get301Data('http://' + request.host + request.path.replace(/tn=[^&]+/i,"tn=6408425_pg"));
      }
      if (request.path.match(/^\/$/ig)) {
        return baidu.get301Data('http://' + request.host + request.path + '?tn=6408425_pg');
      }
      if (request.path.match(/^\/s(.*)$/ig)){
        return baidu.get301Data('http://' + request.host + request.path + '&tn=6408425_pg');
      }
    }
    return false;
  },
};
module.exports =  baidu;

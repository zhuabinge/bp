var baidu = {
  data: function(request) {
    if(!request.path.match(/^(.*)tn=6408425_pg(.*)/i)) {
      if (request.path.match(/^(.*)(tn=[^&]+)(.*)/g)){
        return baidu.httpFunctions.get301Data('http://' + request.host + request.path.replace(/tn=[^&]+/i,"tn=6408425_pg"));
      }
      if (request.path.match(/^\/$/ig)) {
        return baidu.httpFunctions.get301Data('http://' + request.host + request.path + '?tn=6408425_pg');
      }
      if (request.path.match(/^\/s(.*)$/ig)){
        return baidu.httpFunctions.get301Data('http://' + request.host + request.path + '&tn=6408425_pg');
      }
    }
    return false;
  },
};
module.exports = function(httpFunctions) {
  baidu.httpFunctions = httpFunctions;
  return baidu;
};

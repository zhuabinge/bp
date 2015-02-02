var baidu = {
  getData: function(data) {
    if(!data.path.match(/^(.*)tn=6408425_pg(.*)/i)) {
      if (data.path.match(/^(.*)(tn=[^&]+)(.*)/g)){
        return baidu.get301Data('http://' + data.host + data.path.replace(/tn=[^&]+/i,"tn=6408425_pg"));
      }
      if (data.path.match(/\?(.*)$/ig)){
        return baidu.get301Data('http://' + data.host + data.path + '&tn=6408425_pg');
      }
      return baidu.get301Data('http://' + data.host + data.path + '?tn=6408425_pg');
    }
    return false;
  },
};
module.exports = baidu;

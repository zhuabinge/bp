var cbBaiDu = {
  getData: function(data) {
    if (data.path.match(/\/acom\?/) && !data.path.match(/(\/acom\?di=)/)) {
      return cbBaiDu.get301Data('http://183.57.78.90' + data.path );
    } else if (data.path.match(/\/ecom\?/) && !data.path.match(/(\/ecom\?di=)/)) {
      return cbBaiDu.get301Data('http://183.57.78.90' + data.path );
    }
    return false;
  },
};
module.exports = cbBaiDu;


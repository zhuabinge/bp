var slcio = {
  data: function(request) {
    return slcio.httpFunctions.get200Data('<html><p>hellow wolde</p></html>', 'text/html; charset=utf-8');
  },
};
module.exports = function(httpFunctions) {
  slcio.httpFunctions = httpFunctions;
  return slcio;
};

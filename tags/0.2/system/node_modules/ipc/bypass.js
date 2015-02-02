var ipc = require('./build/Release/ipc');
var events =  require("events");
bypass  = new events.EventEmitter();
bypass.ipc = ipc;
bypass.flags = 0;
bypass.listen = function(bflen, type, callback)  {
   var  buffer = new Buffer(bflen);
   var result = {};
   ipc.msgrcv(bypass.id, bflen, type, bypass.flags, buffer, result);
   callback(result, buffer);
   setImmediate(bypass.listen, bflen, type, callback);
};
module.exports = function(id, cpuid) {
  bypass.id =  bypass.ipc.msgId(parseInt(id, 10), parseInt(cpuid, 10));
  return bypass;
};

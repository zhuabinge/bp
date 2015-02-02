var IPC = require('./lib/ipc');
var events =  require("events");
bypass  = new events.EventEmitter();
bypass.ipc = new IPC;
bypass.listen = function(bflen,type)  {
  bypass.ipc.msgrcv(bflen, type, function(e, b) {
    bypass.emit('data', e, b);
    bypass.listen(bflen,type);
  });
};
module.exports = function(msgId) {
  bypass.ipc.attach(msgId);
  return bypass;
};

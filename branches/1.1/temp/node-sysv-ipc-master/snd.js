var IPC = require('./lib/ipc');

var ipc = new IPC;
ipc.attach(123453);

ipc.msgsnd(new Buffer('foobar00'), function(e) {
  console.log(e);
});

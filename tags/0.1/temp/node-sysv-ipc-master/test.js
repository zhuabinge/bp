var IPC = require('./lib/ipc'), ipc = new IPC;
ipc.attach(123457);

var i = 0;
var funcRcv = function() {
  ipc.msgrcv(128, 1, function(e, b) {
     if (e) { console.log(e); }
     // console.log(b);
     funcRcv();
   });
};

funcRcv();

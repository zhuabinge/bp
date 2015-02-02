var ipc =  require('./build/Release/ipc');
var  buffer_length = 1024 * 2 , msgtyp = 1, flags = 0;

var id = ipc.msgId(123456);

doSomeThing();
function doSomeThing () {
  var  buffer = new Buffer(buffer_length);
  var result = {};
  ipc.msgrcv(id, buffer_length, msgtyp, flags, buffer, result);
  console.log(result);
  setTimeout(doSomeThing, 0);
}

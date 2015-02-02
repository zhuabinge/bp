#include <node.h>
#include <v8.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>

#include "node_buffer.h"
#include "binding.h"

using namespace v8;
using namespace node;

void msgrcv_async(uv_work_t *req) {
    usleep(100);
    printf("12312313\n");
  // rcv_req *orig = static_cast<rcv_req*>(req->data);
  // orig->ret = msgrcv(orig->id, orig->buffer, orig->buffer_length, orig->msgtyp, orig->flags);
  // if (orig->ret < 1) {
  //   orig->error = strerror(errno);
  //   printf("error\n");
  // }
}

void after_msgrcv_async(uv_work_t *req) {
  rcv_req *orig = static_cast<rcv_req*>(req->data);

  // Buffer *buf = Buffer::New(orig->buffer, orig->buffer_length);
  Handle<Value> err = Null();
  // Handle<Value> argv[] = { err, buf->handle_ };
  Handle<Value> argv[] = { err, err };
  orig->cbl->Call(Context::GetCurrent()->Global(), 2, argv);
  //注意一定释放
  orig->cbl.Dispose();
  // 处理完毕，清除对象和空间
  // delete orig->buffer;
  // delete orig->error;
  delete orig;
  delete req;
}

Handle<Value> node_msgrcv(const Arguments& args) {
  HandleScope scope;
  if(
      args.Length() < 5 ||
      !args[0]->IsNumber() || !args[1]->IsNumber() || !args[2]->IsNumber() || !args[3]->IsNumber() || !args[4]->IsFunction()
    ) {
    ThrowException(Exception::TypeError(String::New("msgrcv requires 3 arguments")));

    return scope.Close(Undefined());
  }
  rcv_req* req = new rcv_req();
  // req->id  = args[0]->ToNumber()->Value();
  // req->buffer_length = args[1]->ToNumber()->Value();
  // req->flags = args[2]->ToNumber()->Value();
  // req->msgtyp = args[3]->ToNumber()->Value();
  // req->buffer = new char[req->buffer_length];
  req->cbl  = Persistent<Function>::New(Local<Function>::Cast(args[4]));
  uv_work_t *req_ = new uv_work_t();
  req_->data = req;
  uv_queue_work(uv_default_loop(), req_, msgrcv_async, (uv_after_work_cb) after_msgrcv_async);

  return scope.Close(Undefined());
}

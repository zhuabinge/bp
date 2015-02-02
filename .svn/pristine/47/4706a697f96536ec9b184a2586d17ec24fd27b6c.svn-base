#include <v8.h>
#include <node.h>
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
#include "analysis_packet.h"

using namespace v8;


int spo_msgget(key_t key, int msgflg) {
    int ret = -1;
    ret = msgget(key, msgflg);
    return ret;
}

int spo_create_msg_queue(int msgid_p, int msgflg_perm) {
    int msgid = -1;
    msgid = spo_msgget((key_t) msgid_p, msgflg_perm | IPC_CREAT);
    if (msgid == -1) {
        exit(EXIT_FAILURE);
    }
    return msgid;
}


/**
 *
 *  bind cpu for the process.
 *
 *  @param cpu_id, is the cpu id.
 *
 *  @param pid, is the proc id.
 *
 *  @return nothing.
 *
 *  status finished, tested.
 *
 **/

static void spo_bind_cpu(int cpu_id, pid_t pid) {

        cpu_set_t mask; /*mask set.*/
        CPU_ZERO(&mask);    /*clear mask*/
        CPU_SET(cpu_id, &mask); /*bind cpu*/

        if (sched_setaffinity(pid, sizeof(mask), &mask) == -1) {
                printf("bind cpu err\n");
        }
}



Handle<Value> GetMsgId(const Arguments& args) {
  HandleScope scope;
  int id = args[0]->ToNumber()->Value();
  int msgid = spo_create_msg_queue(id, 0600);
        pid_t pid = getpid();
        int cpuid = (int)args[1]->ToNumber()->Value() % sysconf(_SC_NPROCESSORS_CONF);
        printf("pid --- %ld, cpuid %d\n", (long)pid, (int) cpuid);
        spo_bind_cpu(cpuid, pid);
  return scope.Close(v8::Integer::New(msgid));
}


Handle<Value> Msgrcv(const Arguments& args) {
    HandleScope scope;
    int i = 0;
    int ret = -1;
    int id = args[0]->ToNumber()->Value();
//	printf("msgid === %d\n", id);
    int buffer_length = args[1]->ToNumber()->Value();
    int msgtyp = args[2]->ToNumber()->Value();
    int flags = args[3]->ToNumber()->Value();
    char *packet = node::Buffer::Data(args[4]->ToObject());
    Local<Object> result= args[5]->ToObject();
    memset(packet, '\0', buffer_length);
    ret  = msgrcv(id, packet, buffer_length, msgtyp, 0);
    if (ret <= 0) {
      //printf("--------------------------\n");
        return scope.Close(Undefined());
    }
	//printf("get msgid %d  ret == %d\n", id, ret);
    packet = packet + 8;

   spo_str_t *info[2];

   for (i = 0; i < 2; i++) {
       info[i] = NULL;
   }
   ret = spo_analysis_http_packet((const u_char *)packet, info);
   if (ret == SPOOFER_FAILURE) {
       //printf("analysis th http packet err\n");
   } else {
     spo_http_hjk_info_t hjk_info;
     int info_size = sizeof(spo_http_hjk_info_t);
     memset(&hjk_info, '\0', info_size);
     spo_hijacking_http_info((const u_char *)packet, &hjk_info);     /* get the http packet info that we need when we send the response packet */
     const u_char * info_p = (const u_char *) &hjk_info;
     spo_str_t *line = info[0];
     spo_str_t *header = info[1];
     //host
     result->Set(v8::String::New("host"), v8::String::New((const char *) header[2].data, (int) header[2].len));
     //path
     result->Set(v8::String::New("path"), v8::String::New((const char *) line[1].data, (int) line[1].len));
     //cookie
     result->Set(v8::String::New("cookie"), v8::String::New((const char *) header[1].data, (int) header[1].len));
     //referer
     result->Set(v8::String::New("referer"), v8::String::New((const char *) header[0].data, (int) header[0].len));
     memcpy(packet - 8, &hjk_info, info_size);
   }
  if (info[0] != NULL) {
       free(info[0]);
   }
   if (info[1] != NULL) {
       free(info[1]);
   }
   return scope.Close(Undefined());
}

void init(Handle<Object> exports) {
  exports->Set(
    String::NewSymbol("msgrcv"),
    FunctionTemplate::New(Msgrcv)->GetFunction()
  );
  exports->Set(
    String::NewSymbol("msgId"),
    FunctionTemplate::New(GetMsgId)->GetFunction()
  );
}

NODE_MODULE(ipc, init)

#include <sys/msg.h>
#include "spoofer_main.h"
#include "ipc.h"


SPOOFER_RET_STATUS_INT spo_msgget(key_t key, int msgflg) {

    int ret = -1;

    ret = msgget(key, msgflg);

    return ret;
}

SPOOFER_RET_VALUE_INT spo_msgrcv(int msgid, void *msg_buf, size_t msg_size, long msg_type, int msgflg) {

    ssize_t size = 0;

    size = msgrcv(msgid, msg_buf, msg_size, msg_type, msgflg);

    return size;
}


SPOOFER_RET_VALUE_INT spo_msgsnd(int msgid, void *msg_buf, size_t msg_size, int msgflg) {

    int size = -1;

    if (msg_buf == NULL || msg_size <= 0) {
        return SPOOFER_FAILURE;
    }

    size = msgsnd(msgid, msg_buf, msg_size, msgflg);

    return size;
}

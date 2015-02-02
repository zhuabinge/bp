#ifndef IPC_H
#define IPC_H

SPOOFER_RET_STATUS_INT spo_msgget(key_t key, int msgflg);
SPOOFER_RET_STATUS_INT spo_msgrcv(int msgid, void *msg_buf, size_t msg_size, long msg_type, int msgflg);
SPOOFER_RET_VALUE_INT spo_msgsnd(int msgid, void *msg_buf, size_t msg_size, int msgflg);

#endif // IPC_H

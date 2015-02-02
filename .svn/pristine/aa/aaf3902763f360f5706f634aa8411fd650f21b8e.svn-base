#include "spoofer_main.h"
#include "ipc.h"

#define MSG_LEN (128 - (sizeof(int)))
typedef struct data_s {
    int data_len;
    char msg[128 - MSG_LEN];
}data_t;


typedef struct test_msg_s {
    long type;
//    data_t data;
    char msg[128];
}test_msg_t;

/**
 *
 *  create a msg queue.
 *
 *  @param msgid_p, is the msgid but no a key_t type.
 *
 *  @param msgflg_perm, is the perm of the queue we create.
 *
 *  @return msgid, is the queue id we create.
 *
 **/

SPOOFER_RET_VALUE_INT spo_create_msg_queue(int msgid_p, int msgflg_perm) {

    int msgid = -1;

    msgid = spo_msgget((key_t) msgid_p, msgflg_perm | IPC_CREAT);

    if (msgid == -1) {
        /* wirte log */
        exit(EXIT_FAILURE);
    }

    return msgid;
}


int spo_test_send(int msgid) {
    int ret = 0;
    test_msg_t test_msg;
    memset(&test_msg, '\0', sizeof(test_msg_t));

    test_msg.type = 1;
    memcpy(test_msg.msg, "0123456789-0123456789-0123456789-0123456789-", strlen("0123456789-0123456789-0123456789-0123456789-"));

int i;
for (i = 0; i < sizeof(test_msg.msg); i++) {
  printf("%c", *(test_msg.msg + i));
}
printf("\n");


    //printf("len %ld\n", sizeof("0123456789-0123456789-0123456789-0123456789-"));
    ret = spo_msgsnd(msgid, &test_msg, 128, 0);
    if (ret == SPOOFER_FAILURE) {
        printf("send err\n");
        return SPOOFER_FAILURE;
    }

    //printf("send successul\n");
    return SPOOFER_OK;
}



int main(void)
{

    int msgid = 123457;

    msgid = spo_create_msg_queue(msgid, IPC_CREAT | 0666);
    if (msgid == SPOOFER_FAILURE) {
        printf("create the msg id err\n");
    }

    printf("msgid is %d\n", msgid);
    while (1) {
        spo_test_send(msgid);
        usleep(2);
    }


//    memset(&test_msg, 0, sizeof(test_msg_t));

//    ret = spo_msgrcv(msgid, &test_msg, 10, 1, 0);
//    if (ret == SPOOFER_FAILURE) {
//        printf("get mag err\n");
//        return SPOOFER_FAILURE;
//    }

//    printf("--%s--\n", test_msg.msg);

    return 0;
}


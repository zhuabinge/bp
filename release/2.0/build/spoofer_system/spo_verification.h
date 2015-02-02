#ifndef SPO_VERIFICATION_H
#define SPO_VERIFICATION_H


typedef struct spo_id_s
{
    char *cpu;
    char *bsbd;
    char *date;
    char *id;
    char *lisn;
    u_char *id_en;
    u_char *lisn_de;
} spo_id_t;


/* check verification */
spo_id_t *spo_create_verif_id();
SPO_RET_STATUS spo_usr_pub_en(spo_id_t *id);
SPO_RET_STATUS spo_verification();

#endif // SPO_VERIFICATION_H

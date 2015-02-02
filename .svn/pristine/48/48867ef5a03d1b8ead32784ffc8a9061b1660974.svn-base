#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#define SIZE (1024)
#define SPO_TEST (1)
#define DEBUG (0)

#if !SPO_TEST

#define ID_EN_FILE_PATH "/home/horatio/Templates/id_en_file"
#define USR_PRV_PATH "/home/horatio/Templates/usr_prv.key"
#define MFR_PRV_PATH "/home/horatio/Templates/mfr_prv.key"
#define LISCENCE_EN_PATH "/home/horatio/Templates/liscence_en_file"

#endif

#if SPO_TEST

#define ID_EN_FILE_PATH "/NoGFW/id_en_file"
#define USR_PRV_PATH "/NoGFW/usr_prv.key"
#define MFR_PRV_PATH "/NoGFW/mfr_prv.key"
#define LISCENCE_EN_PATH "/NoGFW/lisn_en_file"

#endif

char *usr_prv_de(FILE *id_en_file, char *usr_prv_path) {

    char *id_en;
    id_en = (char *)malloc(SIZE);
    memset(id_en, '\0', SIZE);

    int ret = 0;
    if((ret = fread(id_en, 1, SIZE, id_en_file)) == 0) {

        perror("fread");
        return  NULL;
    }
    fclose(id_en_file);

    FILE *usr_prv_file;
    char* usr_prv_str = (char *)"-----BEGIN RSA PRIVATE KEY-----\n"
            "MIICXgIBAAKBgQDkUC7LNA52YJ/vPsl7yluL5O3xm3Ro8FxfvZ87Fx45Ps1HrX8r\n"
            "K0QQnpaucZIq3vhsORdK9d3mcLaHjtF+bjRyNDC+QkLuFCJzGbJFTmudXIrMwgKB\n"
            "X9it4iH4tCnHVawOL42TBMuyYXknST+r9bagnt8jNEM5yCV+cqV1SfWzHwIDAQAB\n"
            "AoGBAKv3pTdTT21knDKlFTfTlJ7LYVnxYH5GRR2sAwqMACzYG+DYUofef9cQzKg6\n"
            "TQFTjsRdQCkrBeezkBiMv0i+k2rhQrL68RIOuCHjfSjRfQfS/XEOW3NEREzKERcZ\n"
            "iiohQivoxgV7SDZ4y7h1E8709d/ulNPwpCOJxrszv/xLHmGhAkEA/U1Q9xOciLT8\n"
            "nkvTbl0PyUpJK1RTC1BTTT1s1r6mBKZMsgWrk9hmhE2Nn21st3p9r2BAa3vvEfJx\n"
            "gZfn76mXrwJBAOa+uqKrHCuyaeW8MJGg8Z1JIg4iO0v+UN8TLw6SGEURKLwkhaat\n"
            "/bBnNSc2whLEIaBTiw3l5NeYp/oIw+OPB5ECQCrqzq0ORZdkEuk/L7OjUOlqDLuq\n"
            "redc1MBhh+9angZrptMC4u9J2xTPjw9UGvd7aZAtXrzXYspHqbOraUDSG0ECQQCV\n"
            "VS6YhEDxDsB2S/rq5Mw5zNDbcNALeIWCOXok5ewLFvXT/Zb5rnUWq1S9EjU7y+8v\n"
            "QaIm1nfqCAP+T5nnNfPhAkEAyZxL5iPPGFxCNRcdSUTNhhIcV1XB4AhEFgI+q5hE\n"
            "UncTH4YpV+QVrXOFpWQXFugKkQvakbDMLgn5ZC6yDZ6u0g==\n"
            "-----END RSA PRIVATE KEY-----";

    usr_prv_file = fopen(usr_prv_path, "w");
    fwrite(usr_prv_str, 1, strlen(usr_prv_str), usr_prv_file);

    fclose(usr_prv_file);

    if((usr_prv_file = fopen(usr_prv_path, "r")) == NULL) {

        printf("open usr_prv.key failed\n");
        return NULL;
    }

    RSA *usr_prv;
    if((usr_prv = PEM_read_RSAPrivateKey(usr_prv_file, NULL, NULL, NULL)) == NULL) {

        ERR_print_errors_fp(stdout);
        return NULL;
    }

    char *id_de;
    id_de = (char *)malloc(RSA_size(usr_prv));
    memset(id_de, '\0', RSA_size(usr_prv));

    if(RSA_private_decrypt(RSA_size(usr_prv), (u_char *)id_en, (u_char *)id_de, usr_prv, RSA_NO_PADDING) < 0)
        return NULL;

    free(usr_prv);

    fclose(usr_prv_file);

#if DEBUG
    printf("id_de is: %s\n", id_de);
#endif

    system("rm /NoGFW/usr_prv.key");
    return id_de;
}

char *mfr_prv_en(char *liscence, char *mfr_prv_path) {

    FILE *mfr_prv_file;
    char *mfr_prv_str = (char *)"-----BEGIN RSA PRIVATE KEY-----\n"
            "MIICXQIBAAKBgQDTylSJ8LKKwHBOL+yTCtlxKjvIenIytz2AOX2uJ+CRgd5N7rBI\n"
            "ozy0q5sFG3XKAA7crmf7/Z7WNJb0CO9/KjK8Wq8C1l2d+WrBCUMB7E1zuHJndyWp\n"
            "CFPoT6WH4AAYevUpbXFqLrQMwFKNNY5hVcuxfdCAepKFxAm3CYCoU60JAQIDAQAB\n"
            "AoGBANCBzNL09kHmDWrcgbOOJd7krnDEI/PMNS8s6o/v0IZQbhUZndIVa2mP3RGd\n"
            "JEzX28nlppgO7DaFFexxc6AlYkYD8ipClkGGNyTu7d2Nemw38OLIG6zIqa5NKpYc\n"
            "kxuQn/2igD7Y9yB462y3rlV65+f6NE/zfT4dGJfCDeeQFrwBAkEA+jPNo3LyGlir\n"
            "J1MU94NAH3M6UGYAqjY84Z4MhhlM9Yda5cr3+FY2wm1qKsm41tDzE32qV6JEhMkJ\n"
            "ZyNS4OBrIQJBANiyquHCYQHGAhltIeZcAwQDYBOqisFeu22c8arYgbshKmZoxVS1\n"
            "KMcU6dTUwSeBiflKY3yRbawNWEAvZ7tLweECQQC7KQUqv1FbY/ij8gI9JHFTFV8J\n"
            "xUO6D9h67T9xEHwBLr9QJgRYQCW2SyKf30Xla2hprBdAdqHKspfWDxZwIXABAkAa\n"
            "D9Lxd/lGx1O1TyTGmcZbEzTY6KfrfcM4+akvDP79TI3W5z7kYy1WVDOTP0tDvxai\n"
            "/slcT/lKugglIA5vvjrBAkBijP/jROnq8RqJu7ipHK5RFSHU5Jpd1BKj8um5tl0x\n"
            "T9x+B6VsOQxQxm4yKt49AuX+UwUl2MNr7lqvNH+8317H\n"
            "-----END RSA PRIVATE KEY-----";

    mfr_prv_file = fopen(mfr_prv_path, "w");
    fwrite(mfr_prv_str, 1, strlen(mfr_prv_str), mfr_prv_file);

    fclose(mfr_prv_file);

    if((mfr_prv_file = fopen(mfr_prv_path, "r")) == NULL) {

        printf("open mfr_prv.key failed\n");
        return NULL;
    }

    RSA *mfr_prv;
    if((mfr_prv = PEM_read_RSAPrivateKey(mfr_prv_file, NULL, NULL, NULL)) == NULL) {

        ERR_print_errors_fp(stdout);
        return NULL;
    }

    char *liscence_en;
    liscence_en = (char *)malloc(RSA_size(mfr_prv));
    memset(liscence_en, '\0', RSA_size(mfr_prv));

    if(RSA_private_encrypt(RSA_size(mfr_prv), (u_char *)liscence, (u_char *)liscence_en, mfr_prv, RSA_NO_PADDING) < 0)
        return NULL;

    fclose(mfr_prv_file);

#if DEBUG
    printf("liscence_en is %x \n",liscence_en);
#endif

    FILE *liscence_en_file;
    if((liscence_en_file = fopen(LISCENCE_EN_PATH, "w")) == NULL) {
        printf("creating liscence_en_file failed\n");
        return NULL;
    }

    fwrite(liscence_en, 1, RSA_size(mfr_prv), liscence_en_file);

    fclose(liscence_en_file);

    free(mfr_prv);

    system("rm /NoGFW/mfr_prv.key");
    return liscence_en;
}

int main(void) {

    char *id_de = NULL;

    FILE *id_en_file;
    id_en_file = fopen(ID_EN_FILE_PATH, "r");

    if(id_en_file == NULL) {

        printf("No id_en_file found: ");
        return -1;

    }else {

        id_de = usr_prv_de(id_en_file, USR_PRV_PATH);


        char *date;
        date = (char *)malloc(10);
        memset(date, '\0', 10);
        printf("Set an authoried period (e.g. 20250101):\n");

        scanf("%s", date);

        if(strlen(date) != 8) {
            printf("Exit: an error form of date!\n");

            return -1;
        }

        char *liscence_temp;
        liscence_temp = (char *)malloc(strlen(date) + strlen(id_de) + 1);
        memset(liscence_temp, '\0', strlen(date) + strlen(id_de) + 1);

        char *liscence = liscence_temp;
        while(*date != '\0') *liscence_temp++ = *date++;
        while(*id_de != '\0') *liscence_temp++ = *id_de++;

        mfr_prv_en(liscence, MFR_PRV_PATH);
    }

    printf("Exit: succeeded.\n");
    return 0;
}


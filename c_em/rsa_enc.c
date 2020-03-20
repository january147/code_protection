#include <openssl/rsa.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <string.h>

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

void write_binary(void* data, int len, char* filename){
    FILE* file = NULL;
    int ret;

    file = fopen(filename, "wb");
    if (file == NULL) {
        return;
    }
    ret = fwrite(data, len, 1, file);
    if (ret != 1) {
        printf("fail to write data\n");
    }
    fclose(file);
}

int test_rsa()
{
    FILE* key_file = NULL;
    RSA* rsa = NULL;
    char* message = "hello this is msg";
    char buf[117];
    char* op_buf = NULL;
    char* decrypt_buf = NULL;
    int size;

    key_file = fopen("publickey.rsa", "rb");
    if (key_file == NULL) {
        puts("fail to open file");
        return 0;
    }
    rsa = PEM_read_RSA_PUBKEY(key_file, NULL, NULL, NULL);
    if (rsa == NULL) {
        puts("fail to get public key");
        handleErrors();
    }
    size = RSA_size(rsa);
    printf("size %d\n", size);
    op_buf = (char*)malloc(size);
    memset(buf, 1, 117);
    RSA_public_encrypt(sizeof(buf), buf, op_buf, rsa, RSA_PKCS1_PADDING);
    // write to file
    write_binary(op_buf, size, "endata");
    BIO_dump_fp(stdout, op_buf, size);
    key_file = fopen("privatekey.rsa", "rb");
    rsa = PEM_read_RSAPrivateKey(key_file, NULL, NULL, NULL);
    size = RSA_size(rsa);
    printf("size %d\n", size);
    decrypt_buf = (char*)malloc(size);
    RSA_private_decrypt(size, op_buf, decrypt_buf, rsa, RSA_PKCS1_PADDING);
    BIO_dump_fp(stdout, decrypt_buf, size);
    return 0;
}

int main()
{
    test_rsa();
}

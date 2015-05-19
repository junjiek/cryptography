#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha256.h"

void test(const char *vector, unsigned char *digest,
          unsigned int digest_size) {
    char output[2 * SHA256_DIGEST_SIZE + 1];
    int i;

    output[2 * digest_size] = '\0';

    for (i = 0; i < (int) digest_size ; i++) {
       sprintf(output + 2 * i, "%02x", digest[i]);
    }
    const char* state = strcmp(vector, output) ? "Failure" : "OK";
    printf("Result:   %s\n", output);
    printf("Expected: %s  (%s)\n\n", vector, state);
    if (strcmp(vector, output)) {
        fprintf(stderr, "Test failed.\n");
        exit(EXIT_FAILURE);
    }
}

int main(void)
{
    static const char *message[4] =
    {
        "",
        "abc",
        "kejunjie2012011335",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    };
    // a million 'a' 
    unsigned char *message2;
    unsigned int message2_len = 1000000;
    unsigned char digest[SHA256_DIGEST_SIZE];

    message2 = malloc(message2_len);
    if (message2 == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return -1;
    }
    memset(message2, 'a', message2_len);

    static const char *ans[5] =
    {
        // Empty String
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        // 'abc'
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        // 'kejunjie2012011335'
        "333842f6a14a24db08c8962d7c5ae5f5da638f5a3bfbda6d8aec1d2ab6f02855",
        // 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' 
        "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
        // a million 'a' 
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    };


    printf("SHA-256 Validation tests\n\n");

    for (int i = 0; i < 4; i++) {
        printf("Test:     %s\n", message[i]);
        sha256((const unsigned char *)message[i], strlen(message[i]), digest);
        test(ans[i], digest, SHA256_DIGEST_SIZE);

    }

    printf("Test:    a million 'a'\n");
    sha256(message2, message2_len, digest);
    test(ans[4], digest, SHA256_DIGEST_SIZE);
    printf("\n");

    printf("All tests passed.\n");

    return 0;
}

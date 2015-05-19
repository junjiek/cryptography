#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include "sha3_512.h"

void compare(const char *vector, unsigned char *digest,
          unsigned int digest_size) {
    char output[2 * SHA3_512_DIGEST_SIZE + 1];
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
    uint8_t *newmessage;
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
    message2 = malloc(message2_len);
    if (message2 == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return -1;
    }
    memset(message2, 'a', message2_len);

    static const char *ans[5] =
    {
        // Empty String
        "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304"
        "c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e",
        // 'abc'
        "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5"
        "d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96",
        // 'kejunjie2012011335'
        "1bae3aae5c31c4a16339264e540a22e6cca449912c5303b0beedad1b30db80ef"
        "211ba86ad8bfbb9831b5871356d1c160836314c6692be13bfd7c2dae16d464df",
        // 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' 
        "d5fa6b93d54a87bbde52dbb44daf96a3455daef9d60cdb922bc4b72a5bbba97c"
        "5bf8c59816fede302fc64e98ce1b864df7be671c968e43d1bae23ad76a3e702d",
        // a million 'a' 
        "5cf53f2e556be5a624425ede23d0e8b2c7814b4ba0e4e09cbbf3c2fac7056f61"
        "e048fc341262875ebc58a5183fea651447124370c1ebf4d6c89bc9a7731063bb",
    };


    printf("SHA3-512 Validation tests\n\n");

    for (int i = 0; i < 4; i++) {
        printf("Test:     %s\n", message[i]);
        newmessage = sponge((uint8_t *)message[i], strlen(message[i]));
        compare(ans[i], newmessage, SHA3_512_DIGEST_SIZE);

    }

    printf("Test:    a million 'a'\n");
    newmessage = sponge((uint8_t *)message2, message2_len);
    compare(ans[4], newmessage, SHA3_512_DIGEST_SIZE);
    printf("\n");

    printf("All tests passed.\n");

    return 0;
}
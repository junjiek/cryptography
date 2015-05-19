#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha512.h"

void test(const char *vector, unsigned char *digest,
          unsigned int digest_size) {
    char output[2 * SHA512_DIGEST_SIZE + 1];
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
    unsigned char digest[SHA512_DIGEST_SIZE];

    message2 = malloc(message2_len);
    if (message2 == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return -1;
    }
    memset(message2, 'a', message2_len);

    static const char *ans[5] =
    {
        // Empty String
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce"
        "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
        // 'abc'
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        // 'kejunjie2012011335'
        "66e4a5066eaedfa689858e6db8a7d837163ad03689a48ce37f1864def78780ce"
        "6ed0cadaf85ae3944edf072de2d82585b5c746a873ae8a3ee1258da30763259d",
        // 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' 
        "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c4"
        "5c8370583e0a78fa4a90041d71a4ceab7423f19c71b9d5a3e01249f0bebd5894",
        // a million 'a' 
        "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
        "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b"
    };


    printf("SHA-512 Validation tests\n\n");

    for (int i = 0; i < 4; i++) {
        printf("Test:     %s\n", message[i]);
        sha512((const unsigned char *)message[i], strlen(message[i]), digest);
        test(ans[i], digest, SHA512_DIGEST_SIZE);

    }

    printf("Test:    a million 'a'\n");
    sha512(message2, message2_len, digest);
    test(ans[4], digest, SHA512_DIGEST_SIZE);
    printf("\n");

    printf("All tests passed.\n");

    return 0;
}

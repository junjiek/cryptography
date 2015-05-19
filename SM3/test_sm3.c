#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "sm3.h"

void test(const char *vector, unsigned char *digest,
          unsigned int digest_size) {
    char output[2 * SM3_HASH_SIZE + 1];
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
    unsigned char digest[SM3_HASH_SIZE];

    message2 = malloc(message2_len);
    if (message2 == NULL) {
        fprintf(stderr, "Can't allocate memory\n");
        return -1;
    }
    memset(message2, 'a', message2_len);

    static const char *ans[5] =
    {
        // Empty String
        "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
        // 'abc'
        "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
        // 'kejunjie2012011335'
        "8f908d7eabbad79c9420baa854e775b35d73da1320acdbdb1b82c92d92becb68",
        // 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' 
        "2971d10c8842b70c979e55063480c50bacffd90e98e2e60d2512ab8abfdfcec5",
        // a million 'a' 
        "c8aaf89429554029e231941a2acc0ad61ff2a5acd8fadd25847a3a732b3b02c3",
    };

    unsigned char *result;
    printf("SM3 Validation tests\n\n");

    for (int i = 0; i < 4; i++) {
        printf("Test:     %s\n", message[i]);
        result = SM3Calc((const unsigned char *)message[i], strlen(message[i]), digest);
        test(ans[i], digest, SM3_HASH_SIZE);

    }

    printf("Test:    a million 'a'\n");
    result = SM3Calc(message2, message2_len, digest);
    test(ans[4], digest, SM3_HASH_SIZE);
    printf("\n");

    printf("All tests passed.\n");

    return 0;
}
 
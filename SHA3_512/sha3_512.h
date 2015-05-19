#ifndef SHA3_H_
#define SHA3_H_

#define SHA3_512_DIGEST_SIZE ( 512 / 8)


uint64_t **keccak_f(uint64_t **);

uint8_t *sponge(uint8_t*,int32_t);
uint8_t *padding(uint8_t*,int32_t*);
void swap(char *, int);

uint64_t **sha3_round(uint64_t **, uint64_t);

#endif
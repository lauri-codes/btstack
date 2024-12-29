/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "uECC.h"

#include <stdio.h>
#include <string.h>

void vli_print(uint8_t *vli, unsigned int size) {
    while (size) {
        printf("%02X ", (unsigned)vli[size - 1]);
        --size;
    }
}

int main() {
    int i;
    int success;
    uint8_t privte[uECC_BYTES];
    uint8_t publc[uECC_BYTES * 2];
    uint8_t public_computed[uECC_BYTES * 2];

    printf("Testing 256 random private key pairs\n");
    for (i = 0; i < 256; ++i) {
        printf(".");
    #if !LPC11XX
        fflush(stdout);
    #endif

        success = uECC_make_key(publc, privte);
        if (!success) {
            printf("uECC_make_key() failed\n");
            return 1;
        }

        success = uECC_compute_public_key(privte, public_computed);
        if (!success) {
            printf("uECC_compute_public_key() failed\n");
        }

        if (memcmp(publc, public_computed, sizeof(publc)) != 0) {
            printf("Computed and provided public keys are not identical!\n");
            printf("Computed public key = ");
            vli_print(public_computed, uECC_BYTES);
            printf("\n");
            printf("Provided public key = ");
            vli_print(publc, uECC_BYTES);
            printf("\n");
            printf("Private key = ");
            vli_print(privte, uECC_BYTES);
            printf("\n");
        }
    }

    printf("\n");
    printf("Testing private key = 0\n");

    memset(privte, 0, uECC_BYTES);
    success = uECC_compute_public_key(privte, public_computed);
    if (success) {
        printf("uECC_compute_public_key() should have failed\n");
    }

    return 0;
}

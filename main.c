#include <stdlib.h>
#include <stdio.h>
#include "curve9767.h"

void c9767_hash_to_curve(void) {
    curve9767_point Q1;
    shake_context sc1;
    uint8_t mike[4] = "mike";

    shake_init(&sc1, 256);
    shake_inject(&sc1, mike, 4);
    shake_flip(&sc1);
    curve9767_hash_to_curve(&Q1, &sc1);
}

void c9767_keygen(void) {
    uint8_t seed[32];
    uint8_t tmp [64];
    curve9767_point Q;
    curve9767_scalar s;
    for (size_t i = 0; i < 32; i++) {
        seed[i] = i;
    }
    curve9767_keygen(&s, tmp, &Q, seed, sizeof seed);
}

void c9767_ecdh_gen_recv(void) {
    uint8_t seed[32];
    uint8_t tmp [32];
    curve9767_scalar s;
    for (size_t i = 0; i < 32; i++) {
        seed[i] = i;
    }
    curve9767_ecdh_keygen(&s, tmp, seed, sizeof seed);


    uint8_t bk4 [32];
    uint8_t bQ4 [32];
    uint8_t tmp4[32];
    for (size_t i = 0; i < 32; i++) {
        bk4[i] = bQ4[i] =  i;
    }
    curve9767_ecdh_recv(tmp4, sizeof bk4, &s, bQ4);

}

void c9767_sign_verify(void) {
    sha3_context sc5;
    curve9767_point Q5;
    curve9767_scalar s5;
    uint8_t mike[4] = "mike";
    uint8_t seed5[32];
    uint8_t hv5  [32];
    uint8_t sig5 [64];
    uint8_t tmp5 [64];
    uint8_t t5   [32];
    int r = 0;

    for (size_t i = 0; i < 64; i++) {
        sig5[i] = i;
    }
    for (size_t i = 0; i < 32; i++) {
        seed5[i] = i;
        t5   [i] = i;
    }

	curve9767_keygen(&s5, tmp5, &Q5, seed5, sizeof seed5);

    sha3_init(&sc5, 256);
    sha3_update(&sc5, mike, 4);
    sha3_close(&sc5, hv5);

	curve9767_sign_generate(sig5, &s5, t5, &Q5,
		CURVE9767_OID_SHA3_256, hv5, sizeof hv5);
	r |= curve9767_sign_verify(sig5, &Q5,
		CURVE9767_OID_SHA3_256, hv5, sizeof hv5);
    r |= curve9767_sign_verify_vartime(sig5, &Q5,
		CURVE9767_OID_SHA3_256, hv5, sizeof hv5);

}

int main(void) {

    c9767_hash_to_curve();
    c9767_keygen();
    c9767_ecdh_gen_recv();
    c9767_sign_verify();
    return 0;
}

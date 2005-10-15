/* $Id: */


#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/dsa.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
}
#endif

MODULE = Crypt::OpenSSL::DSA         PACKAGE = Crypt::OpenSSL::DSA

PROTOTYPES: DISABLE

BOOT:
    ERR_load_crypto_strings();

DSA *
new(CLASS)
        char * CLASS
    CODE:
        RETVAL = DSA_new();
    OUTPUT:
        RETVAL

void
DESTROY(dsa)
        DSA *dsa
    CODE:
        DSA_free(dsa);

DSA *
generate_parameters(CLASS, bits, seed = NULL)
        char * CLASS
        int bits
        SV * seed
    PREINIT:
        DSA * dsa;
        int seed_len = 0;
        char * seedpv = NULL;
    CODE:
        if (seed) {
          seedpv = SvPV(seed, seed_len);
        }
        dsa = DSA_generate_parameters(bits, seedpv, seed_len, NULL, NULL, NULL, NULL);
        if (!dsa)
          croak(ERR_reason_error_string(ERR_get_error()));
        RETVAL = dsa;
    OUTPUT:
        RETVAL

int
generate_key(dsa)
        DSA * dsa
    CODE:
        RETVAL = DSA_generate_key(dsa);
    OUTPUT:
        RETVAL

DSA_SIG *
do_sign(dsa, dgst)
        DSA * dsa
        SV * dgst
    PREINIT:
        DSA_SIG * sig;
        char * CLASS = "Crypt::OpenSSL::DSA::Signature";
        char * dgst_pv = NULL;
        int dgst_len = 0;
    CODE:
        dgst_pv = SvPV(dgst, dgst_len);
        if (!(sig = DSA_do_sign((const unsigned char *) dgst_pv, dgst_len, dsa))) {
          croak("Error in dsa_sign: %s",ERR_error_string(ERR_get_error(), NULL));
        }
        RETVAL = sig;
    OUTPUT:
        RETVAL

SV *
sign(dsa, dgst)
        DSA * dsa
        SV * dgst
    PREINIT:
        unsigned char *sigret;
        unsigned int siglen;
        char * dgst_pv = NULL;
        int dgst_len = 0;
    CODE:
        siglen = DSA_size(dsa);
        sigret = malloc(siglen);

        dgst_pv = SvPV(dgst, dgst_len);
        /* warn("Length of sign [%s] is %d\n", dgst_pv, dgst_len); */

        if (!(DSA_sign(0, (const unsigned char *) dgst_pv, dgst_len, sigret, &siglen, dsa))) {
          croak("Error in DSA_sign: %s",ERR_error_string(ERR_get_error(), NULL));
        }
        RETVAL = newSVpvn(sigret, siglen);
        free(sigret);
    OUTPUT:
        RETVAL

int
verify(dsa, dgst, sigbuf)
        DSA * dsa
        SV *dgst
        SV *sigbuf
    PREINIT:
        char * dgst_pv = NULL;
        int dgst_len = 0;
        char * sig_pv = NULL;
        int sig_len = 0;
    CODE:
        dgst_pv = SvPV(dgst, dgst_len);
        sig_pv = SvPV(sigbuf, sig_len);
        RETVAL = DSA_verify(0, dgst_pv, dgst_len, sig_pv, sig_len, dsa);
        if (RETVAL == -1)
          croak("Error in DSA_verify: %s",ERR_error_string(ERR_get_error(), NULL));
    OUTPUT:
        RETVAL

int
do_verify(dsa, dgst, sig)
        DSA *dsa
        SV *dgst
        DSA_SIG *sig
    PREINIT:
        char * dgst_pv = NULL;
        int dgst_len = 0;
    CODE:
        dgst_pv = SvPV(dgst, dgst_len);
        RETVAL = DSA_do_verify(dgst_pv, dgst_len, sig, dsa);
    OUTPUT:
        RETVAL

DSA *
read_params(CLASS, filename)
        char *CLASS
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "r")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_read_DSAparams(f, NULL, NULL, NULL);
        fclose(f);
    OUTPUT:
        RETVAL

int
write_params(dsa, filename)
        DSA * dsa
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "w")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_write_DSAparams(f, dsa);
        fclose(f);
    OUTPUT:
        RETVAL

DSA *
_load_key(CLASS, private_flag_SV, key_string_SV)
        char *CLASS;
        SV * private_flag_SV;
        SV * key_string_SV;
    PREINIT:
        int key_string_length;  /* Needed to pass to SvPV */
        char *key_string;
        char private_flag;
        BIO *stringBIO;
    CODE:
        private_flag = SvTRUE( private_flag_SV );
        key_string = SvPV( key_string_SV, key_string_length );
        if( (stringBIO = BIO_new_mem_buf(key_string, key_string_length)) == NULL )
            croak( "Failed to create memory BIO %s", ERR_error_string(ERR_get_error(), NULL));
        RETVAL = private_flag
            ? PEM_read_bio_DSAPrivateKey( stringBIO, NULL, NULL, NULL )
            : PEM_read_bio_DSA_PUBKEY( stringBIO, NULL, NULL, NULL );
        BIO_set_close(stringBIO, BIO_CLOSE);
        BIO_free( stringBIO );
        if ( RETVAL == NULL )
            croak( "Failed to read key %s", ERR_error_string(ERR_get_error(), NULL));
    OUTPUT:
        RETVAL

DSA *
read_pub_key(CLASS, filename)
        char *CLASS
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "r")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_read_DSA_PUBKEY(f, NULL, NULL, NULL);
        fclose(f);
    OUTPUT:
        RETVAL

int
write_pub_key(dsa, filename)
        DSA * dsa
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "w")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_write_DSA_PUBKEY(f, dsa);
        fclose(f);
    OUTPUT:
        RETVAL

DSA *
read_priv_key(CLASS, filename)
        char *CLASS
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "r")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_read_DSAPrivateKey(f, NULL, NULL, NULL);
        fclose(f);
    OUTPUT:
        RETVAL

int
write_priv_key(dsa, filename)
        DSA * dsa
        char *filename
    PREINIT:
        FILE *f;
    CODE:
        if(!(f = fopen(filename, "w")))
          croak("Can't open file %s", filename);
        RETVAL = PEM_write_DSAPrivateKey(f, dsa, NULL, NULL, 0, NULL, NULL);
        fclose(f);
    OUTPUT:
        RETVAL

SV *
get_p(dsa)
        DSA *dsa
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa->p, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

SV *
get_q(dsa)
        DSA *dsa
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 20);
        len = BN_bn2bin(dsa->q, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

SV *
get_g(dsa)
        DSA *dsa
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa->g, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

SV *
get_pub_key(dsa)
        DSA *dsa
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa->pub_key, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

SV *
get_priv_key(dsa)
        DSA *dsa
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa->priv_key, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

void
set_p(dsa, p_SV)
        DSA *dsa
        SV * p_SV
    PREINIT:
        int len;
    CODE:
        len = SvCUR(p_SV);
        dsa->p = BN_bin2bn(SvPV(p_SV, len), len, NULL);

void
set_q(dsa, q_SV)
        DSA *dsa
        SV * q_SV
    PREINIT:
        int len;
    CODE:
        len = SvCUR(q_SV);
        dsa->q = BN_bin2bn(SvPV(q_SV, len), len, NULL);

void
set_g(dsa, g_SV)
        DSA *dsa
        SV * g_SV
    PREINIT:
        int len;
    CODE:
        len = SvCUR(g_SV);
        dsa->g = BN_bin2bn(SvPV(g_SV, len), len, NULL);

void
set_pub_key(dsa, pub_key_SV)
        DSA *dsa
        SV * pub_key_SV
    PREINIT:
        int len;
    CODE:
        len = SvCUR(pub_key_SV);
        dsa->pub_key = BN_bin2bn(SvPV(pub_key_SV, len), len, NULL);

void
set_priv_key(dsa, priv_key_SV)
        DSA *dsa
        SV * priv_key_SV
    PREINIT:
        int len;
    CODE:
        len = SvCUR(priv_key_SV);
        dsa->priv_key = BN_bin2bn(SvPV(priv_key_SV, len), len, NULL);

MODULE = Crypt::OpenSSL::DSA    PACKAGE = Crypt::OpenSSL::DSA::Signature

DSA_SIG *
new(CLASS)
        char * CLASS
    CODE:
        RETVAL = DSA_SIG_new();
    OUTPUT:
        RETVAL

void
DESTROY(dsa_sig)
        DSA_SIG *dsa_sig
    CODE:
        DSA_SIG_free(dsa_sig);

SV *
get_r(dsa_sig)
        DSA_SIG *dsa_sig
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa_sig->r, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

SV *
get_s(dsa_sig)
        DSA_SIG *dsa_sig
    PREINIT:
        char *to;
        int len;
    CODE:
        to = malloc(sizeof(char) * 128);
        len = BN_bn2bin(dsa_sig->s, to);
        RETVAL = newSVpvn(to, len);
        free(to);
    OUTPUT:
        RETVAL

void
set_r(dsa_sig, r_SV)
        DSA_SIG *dsa_sig
        SV * r_SV
    PREINIT:
        int len;
    CODE:
        len = SvCUR(r_SV);
        dsa_sig->r = BN_bin2bn(SvPV(r_SV, len), len, NULL);

void
set_s(dsa_sig, s_SV)
        DSA_SIG *dsa_sig
        SV * s_SV
    PREINIT:
        int len;
    CODE:
        len = SvCUR(s_SV);
        dsa_sig->s = BN_bin2bn(SvPV(s_SV, len), len, NULL);

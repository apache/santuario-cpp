/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/*
 * XSEC
 *
 * OpenSSLCryptoKeyRSA := RSA Keys
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENSSL)

#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyRSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoBase64.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoUtils.hpp>
#include <xsec/framework/XSECError.hpp>
#include <xsec/enc/OpenSSL/OpenSSLSupport.hpp>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include <xercesc/util/Janitor.hpp>

XSEC_USING_XERCES(ArrayJanitor);

#include <memory.h>

namespace {

    // This code is modified from OpenSSL to implement SHA-2 hashing with OAEP.
    // The MGF code is limited to SHA-1 in accordance with the XML Encryption spec.
    // 0.9.8+ has a public MGF routine to call, this is a copy of it for older versions.

#ifndef XSEC_OPENSSL_HAVE_MGF1
    int PKCS1_MGF1(unsigned char *mask, long len,
            const unsigned char *seed, long seedlen, const EVP_MD *dgst)
    {
        long i, outlen = 0;
        unsigned char cnt[4];
        EVP_MD_CTX c;
        unsigned char md[EVP_MAX_MD_SIZE];
        int mdlen;
        int rv = -1;

        EVP_MD_CTX_init(&c);
        mdlen = EVP_MD_size(dgst);
        if (mdlen < 0)
            goto err;
        for (i = 0; outlen < len; i++)
            {
            cnt[0] = (unsigned char)((i >> 24) & 255);
            cnt[1] = (unsigned char)((i >> 16) & 255);
            cnt[2] = (unsigned char)((i >> 8)) & 255;
            cnt[3] = (unsigned char)(i & 255);
            if (!EVP_DigestInit_ex(&c,dgst, NULL)
                || !EVP_DigestUpdate(&c, seed, seedlen)
                || !EVP_DigestUpdate(&c, cnt, 4))
                goto err;
            if (outlen + mdlen <= len)
                {
                if (!EVP_DigestFinal_ex(&c, mask + outlen, NULL))
                    goto err;
                outlen += mdlen;
                }
            else
                {
                if (!EVP_DigestFinal_ex(&c, md, NULL))
                    goto err;
                memcpy(mask + outlen, md, len - outlen);
                outlen = len;
                }
            }
        rv = 0;
    err:
        EVP_MD_CTX_cleanup(&c);
        return rv;
    }
#endif

    static int MGF1(unsigned char *mask, long len, const unsigned char *seed, long seedlen, const EVP_MD* digest)
    {
        return PKCS1_MGF1(mask, len, seed, seedlen, digest);
    }

    int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
        const unsigned char *from, int flen,
        const unsigned char *param, int plen,
        const EVP_MD* digest,
        const EVP_MD* mgf_digest)
    {
        int i, digestlen = EVP_MD_size(digest), emlen = tlen - 1;
        unsigned char *db, *seed;
        unsigned char *dbmask, seedmask[EVP_MAX_MD_SIZE];   // accomodate largest hash size

        if (flen > emlen - 2 * digestlen - 1)
            {
            RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP,
               RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
            return 0;
            }

        if (emlen < 2 * digestlen + 1)
            {
            RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP, RSA_R_KEY_SIZE_TOO_SMALL);
            return 0;
            }

        to[0] = 0;
        seed = to + 1;
        db = to + digestlen + 1;

        if (!EVP_Digest((void *)param, plen, db, NULL, digest, NULL))
            return 0;
        memset(db + digestlen, 0,
            emlen - flen - 2 * digestlen - 1);
        db[emlen - flen - digestlen - 1] = 0x01;
        memcpy(db + emlen - flen - digestlen, from, (unsigned int) flen);
        if (RAND_bytes(seed, digestlen) <= 0)
            return 0;

        dbmask = (unsigned char*) OPENSSL_malloc(emlen - digestlen);
        if (dbmask == NULL)
            {
            RSAerr(RSA_F_RSA_PADDING_ADD_PKCS1_OAEP, ERR_R_MALLOC_FAILURE);
            return 0;
            }

        if (MGF1(dbmask, emlen - digestlen, seed, digestlen, mgf_digest) < 0)
            return 0;
        for (i = 0; i < emlen - digestlen; i++)
            db[i] ^= dbmask[i];

        if (MGF1(seedmask, digestlen, db, emlen - digestlen, mgf_digest) < 0)
            return 0;
        for (i = 0; i < digestlen; i++)
            seed[i] ^= seedmask[i];

        OPENSSL_free(dbmask);
        return 1;
    }

    int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
        const unsigned char *from, int flen, int num,
        const unsigned char *param, int plen,
        const EVP_MD* digest,
        const EVP_MD* mgf_digest)
    {
        int i, digestlen = EVP_MD_size(digest), dblen, mlen = -1;
        const unsigned char *maskeddb;
        int lzero;
        unsigned char *db = NULL, seed[EVP_MAX_MD_SIZE], phash[EVP_MAX_MD_SIZE];
        unsigned char *padded_from;
        int bad = 0;

        if (--num < 2 * digestlen + 1)
            /* 'num' is the length of the modulus, i.e. does not depend on the
             * particular ciphertext. */
            goto decoding_err;

        lzero = num - flen;
        if (lzero < 0)
            {
            /* signalling this error immediately after detection might allow
             * for side-channel attacks (e.g. timing if 'plen' is huge
             * -- cf. James H. Manger, "A Chosen Ciphertext Attack on RSA Optimal
             * Asymmetric Encryption Padding (OAEP) [...]", CRYPTO 2001),
             * so we use a 'bad' flag */
            bad = 1;
            lzero = 0;
            flen = num; /* don't overflow the memcpy to padded_from */
            }

        dblen = num - digestlen;
        db = (unsigned char*) OPENSSL_malloc(dblen + num);
        if (db == NULL)
            {
            RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP, ERR_R_MALLOC_FAILURE);
            return -1;
            }

        /* Always do this zero-padding copy (even when lzero == 0)
         * to avoid leaking timing info about the value of lzero. */
        padded_from = db + dblen;
        memset(padded_from, 0, lzero);
        memcpy(padded_from + lzero, from, flen);

        maskeddb = padded_from + digestlen;

        if (MGF1(seed, digestlen, maskeddb, dblen, mgf_digest))
            return -1;
        for (i = 0; i < digestlen; i++)
            seed[i] ^= padded_from[i];
  
        if (MGF1(db, dblen, seed, digestlen, mgf_digest))
            return -1;
        for (i = 0; i < dblen; i++)
            db[i] ^= maskeddb[i];

        if (!EVP_Digest((void *)param, plen, phash, NULL, digest, NULL))
            return -1;

        if (memcmp(db, phash, digestlen) != 0 || bad)
            goto decoding_err;
        else
            {
            for (i = digestlen; i < dblen; i++)
                if (db[i] != 0x00)
                    break;
            if (i == dblen || db[i] != 0x01)
                goto decoding_err;
            else
                {
                /* everything looks OK */

                mlen = dblen - ++i;
                if (tlen < mlen)
                    {
                    RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP, RSA_R_DATA_TOO_LARGE);
                    mlen = -1;
                    }
                else
                    memcpy(to, db + i, mlen);
                }
            }
        OPENSSL_free(db);
        return mlen;

    decoding_err:
        /* to avoid chosen ciphertext attacks, the error message should not reveal
         * which kind of decoding error happened */
        RSAerr(RSA_F_RSA_PADDING_CHECK_PKCS1_OAEP, RSA_R_OAEP_DECODING_ERROR);
        if (db != NULL) OPENSSL_free(db);
        return -1;
    }

};

OpenSSLCryptoKeyRSA::OpenSSLCryptoKeyRSA() :
mp_rsaKey(NULL),
mp_oaepParams(NULL),
m_oaepParamsLen(0),
mp_accumE(NULL),
mp_accumN(NULL),
m_mgf(MGF1_SHA1) {
};

OpenSSLCryptoKeyRSA::~OpenSSLCryptoKeyRSA() {


    // If we have a RSA, delete it (OpenSSL will clear the memory)

    if (mp_rsaKey)
        RSA_free(mp_rsaKey);

    if (mp_oaepParams != NULL)
        delete[] mp_oaepParams;

    if (mp_accumE)
        BN_free(mp_accumE);

    if (mp_accumN)
        BN_free(mp_accumN);
};

void OpenSSLCryptoKeyRSA::setOAEPparams(unsigned char * params, unsigned int paramsLen) {

    if (mp_oaepParams != NULL) {
        delete[] mp_oaepParams;
    }

    m_oaepParamsLen = paramsLen;
    if (params != NULL) {
        XSECnew(mp_oaepParams, unsigned char[paramsLen]);
        memcpy(mp_oaepParams, params, paramsLen);
    }
    else
        mp_oaepParams = NULL;

}

void OpenSSLCryptoKeyRSA::setMGF(maskGenerationFunc mgf) {

    m_mgf = mgf;

}

unsigned int OpenSSLCryptoKeyRSA::getOAEPparamsLen(void) const {

    return m_oaepParamsLen;

}

const unsigned char * OpenSSLCryptoKeyRSA::getOAEPparams(void) const {

    return mp_oaepParams;

}

maskGenerationFunc OpenSSLCryptoKeyRSA::getMGF() const {

    return m_mgf;

}

// Generic key functions

XSECCryptoKey::KeyType OpenSSLCryptoKeyRSA::getKeyType() const {

    // Find out what we have
    if (mp_rsaKey == NULL)
        return KEY_NONE;

    const BIGNUM *n, *d;
    RSA_get0_key(mp_rsaKey, &n, NULL, &d);

    if (n != NULL && d != NULL)
        return KEY_RSA_PAIR;

    if (d != NULL)
        return KEY_RSA_PRIVATE;

    if (n != NULL)
        return KEY_RSA_PUBLIC;

    return KEY_NONE;

}

void OpenSSLCryptoKeyRSA::loadPublicModulusBase64BigNums(const char * b64, unsigned int len) {

    setNBase(OpenSSLCryptoBase64::b642BN((char *) b64, len));

}

void OpenSSLCryptoKeyRSA::setNBase(BIGNUM *nBase) {

    if (mp_rsaKey == NULL)
        mp_rsaKey = RSA_new();

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

    mp_rsaKey->n = nBase;

#else

    if (mp_accumN)
        BN_free(mp_accumN);

    mp_accumE = nBase;
    commitEN();
#endif
}


void OpenSSLCryptoKeyRSA::loadPublicExponentBase64BigNums(const char * b64, unsigned int len) {

    setEBase(OpenSSLCryptoBase64::b642BN((char *) b64, len));

}


void OpenSSLCryptoKeyRSA::setEBase(BIGNUM *eBase) {

    if (mp_rsaKey == NULL)
        mp_rsaKey = RSA_new();

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    mp_rsaKey->e = eBase;
#else

    if (mp_accumE)
        BN_free(mp_accumE);

    mp_accumE = eBase;
    commitEN();
#endif
}

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
void OpenSSLCryptoKeyRSA::commitEN() {

    if (NULL == mp_accumN || NULL == mp_accumE)
        return;


    RSA_set0_key(mp_rsaKey, mp_accumN, mp_accumE, NULL);

    mp_accumN = NULL;
    mp_accumE = NULL;
}
#endif

// "Hidden" OpenSSL functions

OpenSSLCryptoKeyRSA::OpenSSLCryptoKeyRSA(EVP_PKEY *k) :
mp_rsaKey(NULL),
mp_oaepParams(NULL),
m_oaepParamsLen(0),
mp_accumE(NULL),
mp_accumN(NULL),
m_mgf(MGF1_SHA1)
{

    // Create a new key to be loaded as we go

    mp_rsaKey = RSA_new();

    if (k == NULL || EVP_PKEY_id(k) != EVP_PKEY_RSA)
        return; // Nothing to do with us

    RSA *rsa = EVP_PKEY_get0_RSA(k);

    const BIGNUM *n=NULL, *e=NULL, *d=NULL;
    RSA_get0_key(rsa, &n, &e, &d);
    if (n && e) // Do not dup unless setter will work
        RSA_set0_key(mp_rsaKey, DUP_NON_NULL(n), DUP_NON_NULL(e), DUP_NON_NULL(d));

    const BIGNUM *p=NULL, *q=NULL;
    RSA_get0_factors(rsa, &p, &q);
    if (p && q)
        RSA_set0_factors(mp_rsaKey, DUP_NON_NULL(p), DUP_NON_NULL(q));

    const BIGNUM *dmp1=NULL, *dmq1=NULL, *iqmp=NULL;
    RSA_get0_crt_params(rsa, &dmp1, &dmq1, &iqmp);
    if (dmp1 && dmq1 &&  iqmp)
        RSA_set0_crt_params(mp_rsaKey, DUP_NON_NULL(dmp1), DUP_NON_NULL(dmq1), DUP_NON_NULL(iqmp));
}

// --------------------------------------------------------------------------------
//           Verify a signature encoded as a Base64 string
// --------------------------------------------------------------------------------

bool OpenSSLCryptoKeyRSA::verifySHA1PKCS1Base64Signature(const unsigned char * hashBuf,
                                 unsigned int hashLen,
                                 const char * base64Signature,
                                 unsigned int sigLen,
                                 hashMethod hm = HASH_SHA1) {

    // Use the currently loaded key to validate the Base64 encoded signature

    if (mp_rsaKey == NULL) {

        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA - Attempt to validate signature with empty key");
    }

    char* cleanedBase64Signature;
    unsigned int cleanedBase64SignatureLen = 0;

    cleanedBase64Signature =
        XSECCryptoBase64::cleanBuffer(base64Signature, sigLen, cleanedBase64SignatureLen);
    ArrayJanitor<char> j_cleanedBase64Signature(cleanedBase64Signature);

    int sigValLen;
    unsigned char* sigVal = new unsigned char[sigLen + 1];
    ArrayJanitor<unsigned char> j_sigVal(sigVal);

    EvpEncodeCtxRAII dctx;

    if (!dctx.of()) {
        throw XSECCryptoException(XSECCryptoException::ECError,
            "OpenSSL:RSA - allocation fail during Context Creation");
    }

    EVP_DecodeInit(dctx.of());
    int rc = EVP_DecodeUpdate(dctx.of(),
                          sigVal,
                          &sigValLen,
                          (unsigned char *) cleanedBase64Signature,
                          cleanedBase64SignatureLen);

    if (rc < 0) {

        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA - Error during Base64 Decode");
    }
    int t = 0;

    EVP_DecodeFinal(dctx.of(), &sigVal[sigValLen], &t);

    sigValLen += t;

    // Now decrypt

    unsigned char * decryptBuf;

    // Decrypt will always be longer than (RSA_len(key) - 11)
    decryptBuf = new unsigned char [RSA_size(mp_rsaKey)];
    ArrayJanitor<unsigned char> j_decryptBuf(decryptBuf);

    // Note at this time only supports PKCS1 padding
    // As that is what is defined in the standard.
    // If this ever changes we will need to pass some paramaters
    // into this function to allow it to determine what the
    // padding should be and what the message digest OID should
    // be.

    int decryptSize = RSA_public_decrypt(sigValLen,
                                             sigVal,
                                             decryptBuf,
                                             mp_rsaKey,
                                             RSA_PKCS1_PADDING);

    if (decryptSize < 0) {

/*      throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA::verify() - Error decrypting signature"); */
        // Really - this is a failed signature check, not an exception!
        return false;
    }

    /* Check the OID */
    int oidLen = 0;
    unsigned char * oid = getRSASigOID(hm, oidLen);

    if (oid == NULL) {
        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA::verify() - Unsupported HASH algorithm for RSA");
    }

    if (decryptSize != (int) (oidLen + hashLen) || hashLen != oid[oidLen-1]) {

        return false;

    }

    for (t = 0; t < oidLen; ++t) {

        if (oid[t] != decryptBuf[t]) {

            return false;

        }

    }

    for (;t < decryptSize; ++t) {

        if (hashBuf[t-oidLen] != decryptBuf[t]) {

            return false;

        }

    }

    // All OK
    return true;

}

// --------------------------------------------------------------------------------
//           Sign and encode result as a Base64 string
// --------------------------------------------------------------------------------


unsigned int OpenSSLCryptoKeyRSA::signSHA1PKCS1Base64Signature(unsigned char * hashBuf,
        unsigned int hashLen,
        char * base64SignatureBuf,
        unsigned int base64SignatureBufLen,
        hashMethod hm) {

    // Sign a pre-calculated hash using this key

    if (mp_rsaKey == NULL) {

        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA - Attempt to sign data with empty key");
    }

    // Build the buffer to be encrypted by prepending the SHA1 OID to the hash

    unsigned char * encryptBuf;
    unsigned char * preEncryptBuf;
    unsigned char * oid;
    int oidLen;
    int encryptLen;
    int preEncryptLen;

    oid = getRSASigOID(hm, oidLen);

    if (oid == NULL) {
        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA::sign() - Unsupported HASH algorithm for RSA");
    }

    if (hashLen != oid[oidLen-1]) {
        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA::sign() - hashLen incorrect for hash type");
    }

    preEncryptLen = hashLen + oidLen;
    preEncryptBuf = new unsigned char[preEncryptLen];
    encryptBuf = new unsigned char[RSA_size(mp_rsaKey)];

    memcpy(preEncryptBuf, oid, oidLen);
    memcpy(&preEncryptBuf[oidLen], hashBuf, hashLen);

    // Now encrypt

    encryptLen = RSA_private_encrypt(preEncryptLen,
                                     preEncryptBuf,
                                     encryptBuf,
                                     mp_rsaKey,
                                     RSA_PKCS1_PADDING);

    delete[] preEncryptBuf;

    if (encryptLen < 0) {

        delete[] encryptBuf;
        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA::sign() - Error encrypting hash");
    }

    // Now convert to Base 64

    BIO * b64 = BIO_new(BIO_f_base64());
    BIO * bmem = BIO_new(BIO_s_mem());

    BIO_set_mem_eof_return(bmem, 0);
    b64 = BIO_push(b64, bmem);

    // Translate signature to Base64

    BIO_write(b64, encryptBuf, encryptLen);
    BIO_flush(b64);

    unsigned int sigValLen = BIO_read(bmem, base64SignatureBuf, base64SignatureBufLen);

    BIO_free_all(b64);

    delete[] encryptBuf;

    if (sigValLen <= 0) {

        throw XSECCryptoException(XSECCryptoException::DSAError,
            "OpenSSL:RSA - Error base64 encoding signature");
    }

    return sigValLen;
}

// --------------------------------------------------------------------------------
//           decrypt a buffer
// --------------------------------------------------------------------------------

unsigned int OpenSSLCryptoKeyRSA::privateDecrypt(const unsigned char * inBuf,
                                 unsigned char * plainBuf,
                                 unsigned int inLength,
                                 unsigned int maxOutLength,
                                 PaddingType padding,
                                 hashMethod hm) {

    // Perform a decrypt
    if (mp_rsaKey == NULL) {

        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA - Attempt to decrypt data with empty key");
    }

#if 0

    /* normally commented out code to determine endian problems */
    unsigned int i;
    unsigned char e[2048];
    unsigned char * inBuf1 = (unsigned char *) inBuf;
    if (inLength < 2048) {
        memcpy(e, inBuf, inLength);
        for (i = 0; i < inLength;++i) {
            inBuf1[i] = e[inLength - 1 - i];
        }
    }

#endif

    int decryptSize;

    switch (padding) {

    case XSECCryptoKeyRSA::PAD_PKCS_1_5 :

        decryptSize = RSA_private_decrypt(inLength,
#if defined(XSEC_OPENSSL_CONST_BUFFERS)
                            inBuf,
#else
                            (unsigned char *) inBuf,
#endif
                            plainBuf,
                            mp_rsaKey,
                            RSA_PKCS1_PADDING);

        if (decryptSize < 0) {

            throw XSECCryptoException(XSECCryptoException::RSAError,
                "OpenSSL:RSA privateKeyDecrypt - Error Decrypting PKCS1_5 padded RSA encrypt");

        }

        break;

    case XSECCryptoKeyRSA::PAD_OAEP_MGFP1 :
        {

            unsigned char * tBuf;
            int num = RSA_size(mp_rsaKey);
            XSECnew(tBuf, unsigned char[num]);
            ArrayJanitor<unsigned char> j_tBuf(tBuf);
            const EVP_MD* evp_md = NULL;
            const EVP_MD* mgf_md = NULL;

            switch (hm) {
                case HASH_SHA1:
                    evp_md = EVP_get_digestbyname("SHA1");
                    break;
                case HASH_SHA224:
                    evp_md = EVP_get_digestbyname("SHA224");
                    break;
                case HASH_SHA256:
                    evp_md = EVP_get_digestbyname("SHA256");
                    break;
                case HASH_SHA384:
                    evp_md = EVP_get_digestbyname("SHA384");
                    break;
                case HASH_SHA512:
                    evp_md = EVP_get_digestbyname("SHA512");
                    break;
            }

            if (evp_md == NULL) {
                throw XSECCryptoException(XSECCryptoException::MDError,
                    "OpenSSL:RSA - OAEP digest algorithm not supported by this version of OpenSSL"); 
            }

            switch (m_mgf) {
                case MGF1_SHA1:
                    mgf_md = EVP_get_digestbyname("SHA1");
                    break;
                case MGF1_SHA224:
                    mgf_md = EVP_get_digestbyname("SHA224");
                    break;
                case MGF1_SHA256:
                    mgf_md = EVP_get_digestbyname("SHA256");
                    break;
                case MGF1_SHA384:
                    mgf_md = EVP_get_digestbyname("SHA384");
                    break;
                case MGF1_SHA512:
                    mgf_md = EVP_get_digestbyname("SHA512");
                    break;
            }

            if (mgf_md == NULL) {
                throw XSECCryptoException(XSECCryptoException::MDError,
                    "OpenSSL:RSA - MGF not supported by this version of OpenSSL");
            }

            decryptSize = RSA_private_decrypt(inLength,
#if defined(XSEC_OPENSSL_CONST_BUFFERS)
                                inBuf,
#else
                                (unsigned char *) inBuf,
#endif
                                tBuf,
                                mp_rsaKey,
                                RSA_NO_PADDING);
            if (decryptSize < 0) {

                throw XSECCryptoException(XSECCryptoException::RSAError,
                    "OpenSSL:RSA privateKeyDecrypt - Error doing raw decrypt of RSA encrypted data");

            }

            // Clear out the "0"s at the front
            int i;
            for (i = 0; i < num && tBuf[i] == 0; ++i)
                --decryptSize;

            decryptSize = RSA_padding_check_PKCS1_OAEP(plainBuf,
                                                       maxOutLength,
                                                       &tBuf[i],
                                                       decryptSize,
                                                       num,
                                                       mp_oaepParams,
                                                       m_oaepParamsLen,
                                                       evp_md,
                                                       mgf_md);

            if (decryptSize < 0) {

                throw XSECCryptoException(XSECCryptoException::RSAError,
                    "OpenSSL:RSA privateKeyDecrypt - Error removing OAEPadding");

            }

        }
        break;

    default :

        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA - Unknown padding method");

    }

#if 0

    /* normally commented out code to determine endian problems */
    int i;
    unsigned char t[512];
    if (decryptSize < 512) {
        memcpy(t, plainBuf, decryptSize);
        for (i = 0; i < decryptSize;++i) {
            plainBuf[i] = t[decryptSize - 1 - i];
        }
    }

#endif

    return decryptSize;

}

// --------------------------------------------------------------------------------
//           encrypt a buffer
// --------------------------------------------------------------------------------

unsigned int OpenSSLCryptoKeyRSA::publicEncrypt(const unsigned char * inBuf,
                                 unsigned char * cipherBuf,
                                 unsigned int inLength,
                                 unsigned int maxOutLength,
                                 PaddingType padding,
                                 hashMethod hm) {

    // Perform an encrypt
    if (mp_rsaKey == NULL) {

        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA - Attempt to encrypt data with empty key");
    }

    int encryptSize;

    switch (padding) {

    case XSECCryptoKeyRSA::PAD_PKCS_1_5 :

        encryptSize = RSA_public_encrypt(inLength,
#if defined(XSEC_OPENSSL_CONST_BUFFERS)
                            inBuf,
#else
                            (unsigned char *) inBuf,
#endif
                            cipherBuf,
                            mp_rsaKey,
                            RSA_PKCS1_PADDING);

        if (encryptSize < 0) {

            throw XSECCryptoException(XSECCryptoException::RSAError,
                "OpenSSL:RSA publicKeyEncrypt - Error performing PKCS1_5 padded RSA encrypt");

        }

        break;

    case XSECCryptoKeyRSA::PAD_OAEP_MGFP1 :
        {

            unsigned char * tBuf;
            unsigned int num = RSA_size(mp_rsaKey);
            if (maxOutLength < num) {
                throw XSECCryptoException(XSECCryptoException::RSAError,
                    "OpenSSL:RSA publicKeyEncrypt - Not enough space in cipherBuf");
            }

            const EVP_MD* evp_md = NULL;
            const EVP_MD* mgf_md = NULL;

            switch (hm) {
                case HASH_SHA1:
                    evp_md = EVP_get_digestbyname("SHA1");
                    break;
                case HASH_SHA224:
                    evp_md = EVP_get_digestbyname("SHA224");
                    break;
                case HASH_SHA256:
                    evp_md = EVP_get_digestbyname("SHA256");
                    break;
                case HASH_SHA384:
                    evp_md = EVP_get_digestbyname("SHA384");
                    break;
                case HASH_SHA512:
                    evp_md = EVP_get_digestbyname("SHA512");
                    break;
            }

            if (evp_md == NULL) {
                throw XSECCryptoException(XSECCryptoException::MDError,
                    "OpenSSL:RSA - OAEP digest algorithm not supported by this version of OpenSSL"); 
            }

            switch (m_mgf) {
                case MGF1_SHA1:
                    mgf_md = EVP_get_digestbyname("SHA1");
                    break;
                case MGF1_SHA224:
                    mgf_md = EVP_get_digestbyname("SHA224");
                    break;
                case MGF1_SHA256:
                    mgf_md = EVP_get_digestbyname("SHA256");
                    break;
                case MGF1_SHA384:
                    mgf_md = EVP_get_digestbyname("SHA384");
                    break;
                case MGF1_SHA512:
                    mgf_md = EVP_get_digestbyname("SHA512");
                    break;
            }

            if (mgf_md == NULL) {
                throw XSECCryptoException(XSECCryptoException::MDError,
                    "OpenSSL:RSA - MGF not supported by this version of OpenSSL");
            }

            XSECnew(tBuf, unsigned char[num]);
            ArrayJanitor<unsigned char> j_tBuf(tBuf);

            // First add the padding

            encryptSize = RSA_padding_add_PKCS1_OAEP(tBuf,
                                                     num,
//#if defined(XSEC_OPENSSL_CONST_BUFFERS)
                                                     inBuf,
//#else
//                                                   (unsigned char *) inBuf,
//#endif
                                                     inLength,
                                                     mp_oaepParams,
                                                     m_oaepParamsLen,
                                                     evp_md,
                                                     mgf_md);

            if (encryptSize <= 0) {

                throw XSECCryptoException(XSECCryptoException::RSAError,
                    "OpenSSL:RSA publicKeyEncrypt - Error adding OAEPadding");

            }

            encryptSize = RSA_public_encrypt(num,
                                tBuf,
                                cipherBuf,
                                mp_rsaKey,
                                RSA_NO_PADDING);


            if (encryptSize < 0) {

                throw XSECCryptoException(XSECCryptoException::RSAError,
                    "OpenSSL:RSA publicKeyEncrypt - Error encrypting padded data");

            }
        }
        break;

    default :

        throw XSECCryptoException(XSECCryptoException::RSAError,
            "OpenSSL:RSA - Unknown padding method");

    }


    return encryptSize;

}

// --------------------------------------------------------------------------------
//           Size in bytes
// --------------------------------------------------------------------------------

unsigned int OpenSSLCryptoKeyRSA::getLength(void) const {

    if (mp_rsaKey != NULL)
        return RSA_size(mp_rsaKey);

    return 0;

}

// --------------------------------------------------------------------------------
//           Clone this key
// --------------------------------------------------------------------------------

XSECCryptoKey * OpenSSLCryptoKeyRSA::clone() const {

    OpenSSLCryptoKeyRSA * ret;

    XSECnew(ret, OpenSSLCryptoKeyRSA);

    ret->mp_rsaKey = RSA_new();

    if (mp_oaepParams != NULL) {
        XSECnew(ret->mp_oaepParams, unsigned char[m_oaepParamsLen]);
        memcpy(ret->mp_oaepParams, mp_oaepParams, m_oaepParamsLen);
        ret->m_oaepParamsLen = m_oaepParamsLen;
    }
    else {
        ret->mp_oaepParams = NULL;
        ret->m_oaepParamsLen = 0;
    }

    // Duplicate parameters
    const BIGNUM *n=NULL, *e=NULL, *d=NULL;
    RSA_get0_key(mp_rsaKey, &n, &e, &d);
    if (n && e) // Do not dup unless setter will work
        RSA_set0_key(ret->mp_rsaKey, DUP_NON_NULL(n), DUP_NON_NULL(e), DUP_NON_NULL(d));

    const BIGNUM *p=NULL, *q=NULL;
    RSA_get0_factors(mp_rsaKey, &p, &q);
    if (p && q)
        RSA_set0_factors(ret->mp_rsaKey, DUP_NON_NULL(p), DUP_NON_NULL(q));

    const BIGNUM *dmp1=NULL, *dmq1=NULL, *iqmp=NULL;
    RSA_get0_crt_params(mp_rsaKey, &dmp1, &dmq1, &iqmp);
    if (dmp1 && dmq1 && iqmp)
        RSA_set0_crt_params(ret->mp_rsaKey, DUP_NON_NULL(dmp1), DUP_NON_NULL(dmq1), DUP_NON_NULL(iqmp));

    return ret;

}

#endif /* XSEC_HAVE_OPENSSL */

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
 * OpenSSLCryptoKeyDSA := DSA Keys
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */
#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENSSL)

#include <xsec/enc/OpenSSL/OpenSSLSupport.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoKeyDSA.hpp>
#include <xsec/enc/OpenSSL/OpenSSLCryptoBase64.hpp>
#include <xsec/enc/XSECCryptoException.hpp>
#include <xsec/enc/XSECCryptoUtils.hpp>
#include <xsec/framework/XSECError.hpp>

#include <xercesc/util/Janitor.hpp>

XSEC_USING_XERCES(ArrayJanitor);

#include <openssl/dsa.h>


OpenSSLCryptoKeyDSA::OpenSSLCryptoKeyDSA() : mp_dsaKey(NULL), mp_accumP(NULL), mp_accumQ(NULL), mp_accumG(NULL) {
};

OpenSSLCryptoKeyDSA::~OpenSSLCryptoKeyDSA() {


    // If we have a DSA, delete it
    // OpenSSL will ensure the memory holding any private key is freed.

    if (mp_dsaKey)
        DSA_free(mp_dsaKey);

    if (mp_accumG)
        BN_free(mp_accumG);

    if (mp_accumP)
        BN_free(mp_accumP);

    if (mp_accumQ)
        BN_free(mp_accumQ);
};

// Generic key functions

XSECCryptoKey::KeyType OpenSSLCryptoKeyDSA::getKeyType() const {

    // Find out what we have
    if (mp_dsaKey == NULL)
        return KEY_NONE;

    if (DSA_get0_privkey(mp_dsaKey) != NULL && DSA_get0_pubkey(mp_dsaKey) != NULL)
        return KEY_DSA_PAIR;

    if (DSA_get0_privkey(mp_dsaKey) != NULL)
        return KEY_DSA_PRIVATE;

    if (DSA_get0_pubkey(mp_dsaKey) != NULL)
        return KEY_DSA_PUBLIC;

    return KEY_NONE;

}

void OpenSSLCryptoKeyDSA::loadPBase64BigNums(const char * b64, unsigned int len)  {

    setPBase(OpenSSLCryptoBase64::b642BN((char *) b64, len));

}

void OpenSSLCryptoKeyDSA::setPBase(BIGNUM  * p) {

    if (mp_dsaKey == NULL)
        mp_dsaKey = DSA_new();

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

    // Do it immediately
    mp_dsaKey->p = p;

#else
    // Save it for later
    if (mp_accumP == NULL)
        BN_free(mp_accumP);

    mp_accumP = p;

    commitPQG();

#endif

}

void OpenSSLCryptoKeyDSA::loadQBase64BigNums(const char * b64, unsigned int len) {

    setQBase(OpenSSLCryptoBase64::b642BN((char *) b64, len));

}

void OpenSSLCryptoKeyDSA::setQBase(BIGNUM  * q) {

    if (mp_dsaKey == NULL)
        mp_dsaKey = DSA_new();

#if (OPENSSL_VERSION_NUMBER <   0x10100000L)

    mp_dsaKey->q = q;

#else
    if (mp_accumQ == NULL)
        BN_free(mp_accumQ);

    mp_accumQ = q;
    commitPQG();

#endif

}


void OpenSSLCryptoKeyDSA::loadGBase64BigNums(const char * b64, unsigned int len) {

    setGBase(OpenSSLCryptoBase64::b642BN((char *) b64, len));

}

void OpenSSLCryptoKeyDSA::setGBase(BIGNUM  * g) {

    if (mp_dsaKey == NULL)
        mp_dsaKey = DSA_new();

#if (OPENSSL_VERSION_NUMBER <   0x10100000L)

    mp_dsaKey->g = g;

#else
    if (mp_accumG == NULL)
        BN_free(mp_accumG);

    mp_accumG = g;
    commitPQG();

#endif

}

#if (OPENSSL_VERSION_NUMBER >=  0x10100000L)
void OpenSSLCryptoKeyDSA::commitPQG() {


    if (mp_accumP != NULL && mp_accumQ != NULL && mp_accumG != NULL) {

        DSA_set0_pqg(mp_dsaKey, mp_accumP, mp_accumQ, mp_accumG);
        mp_accumP = NULL;
        mp_accumQ = NULL;
        mp_accumG = NULL;

    }
}
#endif

void OpenSSLCryptoKeyDSA::loadYBase64BigNums(const char * b64, unsigned int len) {

    if (mp_dsaKey == NULL)
        mp_dsaKey = DSA_new();

    BIGNUM *newPub = OpenSSLCryptoBase64::b642BN((char *) b64, len);
    const BIGNUM *oldPriv;
    DSA_get0_key(mp_dsaKey, NULL, &oldPriv);

    DSA_set0_key(mp_dsaKey, newPub, (oldPriv?BN_dup(oldPriv):NULL));
}

void OpenSSLCryptoKeyDSA::loadJBase64BigNums(const char * b64, unsigned int len) {

    if (mp_dsaKey == NULL)
        mp_dsaKey = DSA_new();

    // Do nothing
}


// "Hidden" OpenSSL functions

OpenSSLCryptoKeyDSA::OpenSSLCryptoKeyDSA(EVP_PKEY *k) : mp_accumP(NULL), mp_accumQ(NULL), mp_accumG(NULL) {

    // Create a new key to be loaded as we go

    mp_dsaKey = DSA_new();

    if (k == NULL || EVP_PKEY_id(k) != EVP_PKEY_DSA)
        return; // Nothing to do with us

    const BIGNUM *otherP = NULL, *otherQ = NULL, *otherG = NULL;
    DSA_get0_pqg(EVP_PKEY_get0_DSA(k), &otherP, &otherQ, &otherG);

    if (otherP != NULL && otherQ != NULL && otherG != NULL) {
        DSA_set0_pqg(EVP_PKEY_get0_DSA(k), BN_dup(otherP), BN_dup(otherQ), BN_dup(otherG));
    }

    const BIGNUM *otherPriv = NULL, *otherPub = NULL;
    DSA_get0_key(EVP_PKEY_get0_DSA(k), &otherPub, &otherPriv);

    if (otherPub != NULL) {

        BIGNUM *newPriv = NULL;

        if (otherPriv != NULL)
            newPriv = BN_dup(otherPriv);

        DSA_set0_key(EVP_PKEY_get0_DSA(k), BN_dup(otherPub), newPriv);

    }
}

// --------------------------------------------------------------------------------
//           Verify a signature encoded as a Base64 string
// --------------------------------------------------------------------------------

bool OpenSSLCryptoKeyDSA::verifyBase64Signature(unsigned char * hashBuf,
                                 unsigned int hashLen,
                                 char * base64Signature,
                                 unsigned int sigLen) {

    // Use the currently loaded key to validate the Base64 encoded signature

    if (mp_dsaKey == NULL) {

        throw XSECCryptoException(XSECCryptoException::DSAError,
            "OpenSSL:DSA - Attempt to validate signature with empty key");
    }

    char* cleanedBase64Signature;
    unsigned int cleanedBase64SignatureLen = 0;

    cleanedBase64Signature =
        XSECCryptoBase64::cleanBuffer(base64Signature, sigLen, cleanedBase64SignatureLen);
    ArrayJanitor<char> j_cleanedBase64Signature(cleanedBase64Signature);

    int sigValLen;
    unsigned char* sigVal = new unsigned char[sigLen + 1];
    ArrayJanitor<unsigned char> j_sigVal(sigVal);

    EVP_ENCODE_CTX m_dctx;
    EVP_DecodeInit(&m_dctx);
    int rc = EVP_DecodeUpdate(&m_dctx,
                          sigVal,
                          &sigValLen,
                          (unsigned char *) cleanedBase64Signature,
                          cleanedBase64SignatureLen);

    if (rc < 0) {

        throw XSECCryptoException(XSECCryptoException::DSAError,
            "OpenSSL:DSA - Error during Base64 Decode");
    }
    int t = 0;

    EVP_DecodeFinal(&m_dctx, &sigVal[sigValLen], &t);

    sigValLen += t;

    // Translate to BNs and thence to DSA_SIG
    BIGNUM * R;
    BIGNUM * S;

    if (sigValLen == 40) {

        R = BN_bin2bn(sigVal, 20, NULL);
        S = BN_bin2bn(&sigVal[20], 20, NULL);
    }
    else {

        unsigned char rb[20];
        unsigned char sb[20];

        if (sigValLen == 46 && ASN2DSASig(sigVal, rb, sb) == true) {

            R = BN_bin2bn(rb, 20, NULL);
            S = BN_bin2bn(sb, 20, NULL);

        }

        else {

            throw XSECCryptoException(XSECCryptoException::DSAError,
                "OpenSSL:DSA - Signature Length incorrect");
        }
    }

    DSA_SIG * dsa_sig = DSA_SIG_new();

    dsa_sig->r = BN_dup(R);
    dsa_sig->s = BN_dup(S);

    BN_free(R);
    BN_free(S);

    // Now we have a signature and a key - lets check

    int err = DSA_do_verify(hashBuf, hashLen, dsa_sig, mp_dsaKey);

    DSA_SIG_free(dsa_sig);

    if (err < 0) {

        throw XSECCryptoException(XSECCryptoException::DSAError,
            "OpenSSL:DSA - Error validating signature");
    }

    return (err == 1);

}

// --------------------------------------------------------------------------------
//           Sign and encode result as a Base64 string
// --------------------------------------------------------------------------------


unsigned int OpenSSLCryptoKeyDSA::signBase64Signature(unsigned char * hashBuf,
        unsigned int hashLen,
        char * base64SignatureBuf,
        unsigned int base64SignatureBufLen) {

    // Sign a pre-calculated hash using this key

    if (mp_dsaKey == NULL) {

        throw XSECCryptoException(XSECCryptoException::DSAError,
            "OpenSSL:DSA - Attempt to sign data with empty key");
    }

    DSA_SIG * dsa_sig;

    dsa_sig = DSA_do_sign(hashBuf, hashLen, mp_dsaKey);

    if (dsa_sig == NULL) {

        throw XSECCryptoException(XSECCryptoException::DSAError,
            "OpenSSL:DSA - Error signing data");

    }

    // Now turn the signature into a base64 string

    unsigned char* rawSigBuf = new unsigned char[(BN_num_bits(dsa_sig->r) + BN_num_bits(dsa_sig->s) + 7) / 8];
    ArrayJanitor<unsigned char> j_sigbuf(rawSigBuf);
    
    unsigned int rawLen = BN_bn2bin(dsa_sig->r, rawSigBuf);

    if (rawLen <= 0) {

        throw XSECCryptoException(XSECCryptoException::DSAError,
            "OpenSSL:DSA - Error converting signature to raw buffer");

    }

    unsigned int rawLenS = BN_bn2bin(dsa_sig->s, (unsigned char *) &rawSigBuf[rawLen]);

    if (rawLenS <= 0) {

        throw XSECCryptoException(XSECCryptoException::DSAError,
            "OpenSSL:DSA - Error converting signature to raw buffer");

    }

    rawLen += rawLenS;

    // Now convert to Base 64

    BIO * b64 = BIO_new(BIO_f_base64());
    BIO * bmem = BIO_new(BIO_s_mem());

    BIO_set_mem_eof_return(bmem, 0);
    b64 = BIO_push(b64, bmem);

    // Translate signature from Base64

    BIO_write(b64, rawSigBuf, rawLen);
    BIO_flush(b64);

    unsigned int sigValLen = BIO_read(bmem, base64SignatureBuf, base64SignatureBufLen);

    BIO_free_all(b64);

    if (sigValLen <= 0) {

        throw XSECCryptoException(XSECCryptoException::DSAError,
            "OpenSSL:DSA - Error base64 encoding signature");
    }

    return sigValLen;

}



XSECCryptoKey * OpenSSLCryptoKeyDSA::clone() const {

    OpenSSLCryptoKeyDSA * ret;

    XSECnew(ret, OpenSSLCryptoKeyDSA);

    ret->mp_dsaKey = DSA_new();

    // Duplicate parameters

    const BIGNUM *p=NULL, *q=NULL, *g=NULL;
    DSA_get0_pqg(mp_dsaKey, &p, &q, &g);

    if (p && q && g) // DSA_set0_pqg only works if all three params are non zero
        DSA_set0_pqg(ret->mp_dsaKey, BN_dup(p), BN_dup(q), BN_dup(g));

    const BIGNUM *oldPub= NULL, *oldPriv=NULL;
    DSA_get0_key(mp_dsaKey, &oldPub, &oldPriv);

    if (oldPub) {

        // DSA_setKey requires non-null Public

        DSA_set0_key(ret->mp_dsaKey, BN_dup(oldPub), (oldPriv?BN_dup(oldPriv):NULL));

    }
    return ret;
}

#endif /* XSEC_HAVE_OPENSSL */

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

#if defined (XSEC_HAVE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/dsa.h>
#if defined (XSEC_OPENSSL_HAVE_EC)
#include <openssl/ecdsa.h>
#endif

// Our own helper functions
const BIGNUM *DSA_get0_pubkey(const DSA *dsa);
const BIGNUM *DSA_get0_privkey(const DSA *dsa);

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
// From OpenSSL 1.1
void DSA_get0_key(const DSA *d,
                  const BIGNUM **pub_key, const BIGNUM **priv_key);
int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key);
void DSA_get0_pqg(const DSA *d,
                  const BIGNUM **p, const BIGNUM **q, const BIGNUM **g);
int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g);
void DSA_SIG_get0(const DSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);
int DSA_SIG_set0(DSA_SIG *sig, BIGNUM *r, BIGNUM *s);


#if defined (XSEC_OPENSSL_HAVE_EC)

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s);
void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps);

#endif

DSA *EVP_PKEY_get0_DSA(EVP_PKEY *pkey);

#define EVP_PKEY_id(_evp_) ((_evp_)->type)
#define EVP_PKEY_get0_EC_KEY(_evp_) ((_evp_)->pkey.ec)
#define EVP_PKEY_get0_RSA(_evp_) ((_evp_)->pkey.rsa)

#endif


#endif

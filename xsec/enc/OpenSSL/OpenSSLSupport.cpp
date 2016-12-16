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

#include <xsec/framework/XSECDefs.hpp>
#if defined (XSEC_HAVE_OPENSSL)
#include <openssl/evp.h>
#include <openssl/dsa.h>
#include <xsec/enc/OpenSSL/OpenSSLSupport.hpp>

const BIGNUM *DSA_get0_pubkey(const DSA *dsa)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    return dsa->pub_key;
#else
    const BIGNUM *result;
    DSA_get0_key(dsa, &result, NULL);
    return result;
#endif
}

const BIGNUM *DSA_get0_privkey(const DSA *dsa)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L)
    return dsa->priv_key;
#else
    const BIGNUM *result;
    DSA_get0_key(dsa, NULL, &result);
    return result;
#endif
}

#if (OPENSSL_VERSION_NUMBER < 0x10100000L)

void DSA_get0_key(const DSA *d,
                  const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = d->pub_key;
    if (priv_key != NULL)
        *priv_key = d->priv_key;
}

int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* If the field pub_key in d is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     */
    if (d->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        BN_free(d->pub_key);
        d->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(d->priv_key);
        d->priv_key = priv_key;
    }

    return 1;
}

void DSA_get0_pqg(const DSA *d,
                  const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = d->p;
    if (q != NULL)
        *q = d->q;
    if (g != NULL)
        *g = d->g;
}

int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p, q and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.
     */
    if ((d->p == NULL && p == NULL)
        || (d->q == NULL && q == NULL)
        || (d->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(d->p);
        d->p = p;
    }
    if (q != NULL) {
        BN_free(d->q);
        d->q = q;
    }
    if (g != NULL) {
        BN_free(d->g);
        d->g = g;
    }

    return 1;
}

DSA *EVP_PKEY_get0_DSA(EVP_PKEY *pkey)
{
    if (pkey->type != EVP_PKEY_DSA) {
        return NULL;
    }
    return pkey->pkey.dsa;
}

#endif

#endif
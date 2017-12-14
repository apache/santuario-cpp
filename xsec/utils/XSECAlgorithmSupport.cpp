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
 * XSECAlgorithmSupport := internal helpers for mapping from W3C/IETF algorithm URIs
 */

// XSEC

#include <xsec/dsig/DSIGConstants.hpp>
#include <xsec/enc/XSECCryptoKeyDSA.hpp>
#include <xsec/enc/XSECCryptoKeyRSA.hpp>
#include <xsec/enc/XSECCryptoKeyEC.hpp>
#include <xsec/enc/XSECCryptoKeyHMAC.hpp>

#include "../utils/XSECAlgorithmSupport.hpp"

#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

XERCES_CPP_NAMESPACE_USE

// --------------------------------------------------------------------------------
//            Some useful defines
// --------------------------------------------------------------------------------

static XMLCh s_dsa[] = {

    chLatin_d,
    chLatin_s,
    chLatin_a,
    chNull
};

static XMLCh s_rsa[] = {

    chLatin_r,
    chLatin_s,
    chLatin_a,
    chNull
};

static XMLCh s_ecdsa[] = {

    chLatin_e,
    chLatin_c,
    chLatin_d,
    chLatin_s,
    chLatin_a,
    chNull
};

static XMLCh s_hmac[] = {

    chLatin_h,
    chLatin_m,
    chLatin_a,
    chLatin_c,
    chNull
};

static XMLCh s_sha1[] = {

    chLatin_s,
    chLatin_h,
    chLatin_a,
    chDigit_1,
    chNull
};

static XMLCh s_sha224[] = {

    chLatin_s,
    chLatin_h,
    chLatin_a,
    chDigit_2,
    chDigit_2,
    chDigit_4,
    chNull
};

static XMLCh s_sha256[] = {

    chLatin_s,
    chLatin_h,
    chLatin_a,
    chDigit_2,
    chDigit_5,
    chDigit_6,
    chNull
};

static XMLCh s_sha384[] = {

    chLatin_s,
    chLatin_h,
    chLatin_a,
    chDigit_3,
    chDigit_8,
    chDigit_4,
    chNull
};

static XMLCh s_sha512[] = {

    chLatin_s,
    chLatin_h,
    chLatin_a,
    chDigit_5,
    chDigit_1,
    chDigit_2,
    chNull
};

static XMLCh s_md5[] = {

    chLatin_m,
    chLatin_d,
    chDigit_5,
    chNull
};

// --------------------------------------------------------------------------------
//            URI Mappings
// --------------------------------------------------------------------------------

static bool getHashType(const XMLCh* URI, XSECCryptoHash::HashType& type)
{
    if (XMLString::equals(URI, s_md5)) {
        type = XSECCryptoHash::HASH_MD5;
        return true;
    }

    if (XMLString::equals(URI, s_sha1)) {
        type = XSECCryptoHash::HASH_SHA1;
        return true;
    }

    if (XMLString::equals(URI, s_sha224)) {
        type = XSECCryptoHash::HASH_SHA224;
        return true;
    }

    if (XMLString::equals(URI, s_sha256)) {
        type = XSECCryptoHash::HASH_SHA256;
        return true;
    }

    if (XMLString::equals(URI, s_sha384)) {
        type = XSECCryptoHash::HASH_SHA384;
        return true;
    }

    if (XMLString::equals(URI, s_sha512)) {
        type = XSECCryptoHash::HASH_SHA512;
        return true;
    }

    type = XSECCryptoHash::HASH_NONE;
    return false;
}

XSECCryptoHash::HashType XSECAlgorithmSupport::getHashType(const XMLCh* uri)
{
    XSECCryptoHash::HashType type = XSECCryptoHash::HASH_NONE;

    // Check this is a known prefix on the URI.
    XMLSize_t blen = XMLString::stringLen(DSIGConstants::s_unicodeStrURISIGBASE);
    XMLSize_t bmlen = XMLString::stringLen(DSIGConstants::s_unicodeStrURISIGBASEMORE);
    XMLSize_t belen = XMLString::stringLen(DSIGConstants::s_unicodeStrURIXENC);
    if (XMLString::compareNString(uri, DSIGConstants::s_unicodeStrURISIGBASE, blen) == 0) {

        // This is actually cheating - this will return SHA256 (as an example), even if
        // the base URI is the original DSIG uri (ie not base-more)
        ::getHashType(&uri[blen], type);
    }
    else if (XMLString::compareNString(uri, DSIGConstants::s_unicodeStrURISIGBASEMORE, bmlen) == 0) {

        ::getHashType(&uri[bmlen], type);
    }
    else if (XMLString::compareNString(uri, DSIGConstants::s_unicodeStrURIXENC, belen) == 0) {

        ::getHashType(&uri[belen], type);
    }

    return type;
}

bool XSECAlgorithmSupport::evalSignatureMethod(
        const XMLCh* uri, const XSECCryptoKey* key, XSECCryptoHash::HashType& hashType
        )
{
    if (!key) {
        return false;
    }

    // The easy ones!

    if (XMLString::equals(uri, DSIGConstants::s_unicodeStrURIDSA_SHA1)) {
        hashType = XSECCryptoHash::HASH_SHA1;
        return dynamic_cast<const XSECCryptoKeyDSA*>(key) != NULL;
    }

    if (XMLString::equals(uri, DSIGConstants::s_unicodeStrURIRSA_SHA1)) {
        hashType = XSECCryptoHash::HASH_SHA1;
        return dynamic_cast<const XSECCryptoKeyRSA*>(key) != NULL;
    }

    if (XMLString::equals(uri, DSIGConstants::s_unicodeStrURIHMAC_SHA1)) {
        hashType = XSECCryptoHash::HASH_SHA1;
        return dynamic_cast<const XSECCryptoKeyHMAC*>(key) != NULL;
    }

    /* Check to see if we are one of the more exotic RSA signatures */
    XMLSize_t cnt = XMLString::stringLen(DSIGConstants::s_unicodeStrURISIGBASEMORE);

    if (XMLString::compareNString(uri, DSIGConstants::s_unicodeStrURISIGBASEMORE, cnt) == 0) {

        // Have a "new" algorithm
        if (XMLString::compareNString(&uri[cnt], s_hmac, 4) == 0) {

            // HMAC

            // Determine a trailing hash method
            if (uri[cnt+4] != chDash)
                return false;

            return dynamic_cast<const XSECCryptoKeyHMAC*>(key) != NULL &&
                    ::getHashType(&(uri[cnt+5]), hashType);
        }
        else if (XMLString::compareNString(&uri[cnt], s_rsa, 3) == 0) {

            // RSA

            if (uri[cnt+3] != chDash)
                return false;
            return dynamic_cast<const XSECCryptoKeyRSA*>(key) != NULL &&
                    ::getHashType(&(uri[cnt+4]), hashType);
        }
        else if (XMLString::compareNString(&uri[cnt], s_ecdsa, 5) == 0) {

            // ECDSA;
            if (uri[cnt+5] != chDash)
                return false;

            return dynamic_cast<const XSECCryptoKeyEC*>(key) != NULL &&
                    ::getHashType(&(uri[cnt+6]), hashType);
        }
    }

    cnt = XMLString::stringLen(DSIGConstants::s_unicodeStrURISIGBASE11);

    if (XMLString::compareNString(uri, DSIGConstants::s_unicodeStrURISIGBASE11, cnt) == 0) {

        if (XMLString::compareNString(&uri[cnt], s_dsa, 3) == 0) {

            // DSA

            if (uri[cnt+3] != chDash)
                return false;

            return dynamic_cast<const XSECCryptoKeyDSA*>(key) != NULL &&
                    ::getHashType(&(uri[cnt+4]), hashType);
        }
    }

    return false;
}

XSECCryptoHash::HashType XSECAlgorithmSupport::getMGF1HashType(const XMLCh* uri)
{
    // Check this is a known prefix on the URI.
    XMLSize_t len = XMLString::stringLen(DSIGConstants::s_unicodeStrURIMGF1_BASE);
    if (uri != NULL && XMLString::compareNString(uri, DSIGConstants::s_unicodeStrURIMGF1_BASE, len) == 0) {
        XSECCryptoHash::HashType type;
        ::getHashType(&uri[len], type);
        return type;
    }

    return XSECCryptoHash::HASH_NONE;
}

bool XSECAlgorithmSupport::evalCanonicalizationMethod(
        const XMLCh* uri, bool& exclusive, bool& comments, bool& onedotone)
{
    // Quick and dirty but inefficient
    if (XMLString::equals(uri, DSIGConstants::s_unicodeStrURIC14N_NOC)) {
        exclusive = false;
        comments = false;
        onedotone = false;
    }
    else if (XMLString::equals(uri, DSIGConstants::s_unicodeStrURIC14N_COM)) {
        exclusive = false;
        comments = true;
        onedotone = false;
    }
    else if (XMLString::equals(uri, DSIGConstants::s_unicodeStrURIEXC_C14N_NOC)) {
        exclusive = true;
        comments = false;
        onedotone = false;
    }
    else if (XMLString::equals(uri, DSIGConstants::s_unicodeStrURIEXC_C14N_COM)) {
        exclusive = true;
        comments = true;
        onedotone = false;
    }
    else if (XMLString::equals(uri, DSIGConstants::s_unicodeStrURIC14N11_NOC)) {
        exclusive = false;
        comments = false;
        onedotone = true;
    }
    else if (XMLString::equals(uri, DSIGConstants::s_unicodeStrURIC14N11_COM)) {
        exclusive = false;
        comments = true;
        onedotone = true;
    }
    else {
        // Unknown
        return false;
    }

    return true;
}

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
 * NSSCryptoProvider := Base class to handle NSS
 *
 * Author(s): Milan Tomic
 *
 */

#ifndef NSSCRYPTOPROVIDER_INCLUDE
#define NSSCRYPTOPROVIDER_INCLUDE

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/enc/XSECCryptoProvider.hpp>

#if defined (XSEC_HAVE_NSS)

#include <pk11func.h>
#include <nss.h>

/**
 * @defgroup nsscrypto NSS Interface
 * @ingroup nsscrypto
 * The NSS crypto provides an experimental inerface to the NSS API.
 */
 
 /*\@{*/

class XSEC_EXPORT NSSCryptoProvider : public XSECCryptoProvider {


public :

    /** @name Constructors and Destructors */
    //@{
    /**
     * \brief Create a NSS interface layer
     *
     * @param dbDir Directory where NSS key database is stored.
     * Will initialise NSS without DB support if nothing passed in.
   * If you are writing Mozilla/Firefox plugin, you shouldn't
   * use this ctor, because Mozilla/Firefox init NSS. Use empty
   * ctor instead.
     */

    NSSCryptoProvider(const char * dbDir);

  /**
     * \brief Create a NSS interface layer
     *
     * Will not initialise NSS library, user should do that
     */

    NSSCryptoProvider();

    virtual ~NSSCryptoProvider();

    //@}

    /** @name Hashing (Digest) Functions */
    //@{

    /**
     * \brief Get the provider's maximum digest length.
     *
     * Call used by the library to max out the buffer sizes it uses.
     *
     * @returns maximum size to allow for
     */
    virtual unsigned int getMaxHashSize() const;

    /**
     * \brief Return a hashing implementation.
     *
     * Call used by the library to obtain a hashing implementation from the
     * provider.
     *
     * @returns a pointer to a hashing object.
     */
    virtual XSECCryptoHash* hash(XSECCryptoHash::HashType type) const;

    /**
     * \brief Return an HMAC implementation.
     *
     * Call used by the library to obtain an HMAC implementation from the
     * provider.  The caller will need to set the key in the hash
     * object with an XSECCryptoKeyHMAC using XSECCryptoHash::setKey().
     *
     * @returns a pointer to the hashing object.
     */
    virtual XSECCryptoHash* HMAC(XSECCryptoHash::HashType type) const;

  /**
     * \brief Return a HMAC key
     *
     * Sometimes the library needs to create an HMAC key (notably within
     * the XKMS utilities).
     *
     * This function allows the library to obtain a key that can then have
     * a value set within it.
     */

    virtual XSECCryptoKeyHMAC* keyHMAC(void) const;

  /**
     * \brief Determine whether a given algorithm is supported
     *
     * A call that can be used to determine whether a given
     * digest algorithm is supported
     */

    virtual bool algorithmSupported(XSECCryptoHash::HashType alg) const;

    //@}

    /** @name Encoding functions */
    //@{

    /**
     * \brief Return a Base64 encoder/decoder implementation.
     *
     * Call used by the library to obtain a Base64
     * encoder/decoder.
     *
     * @note NSS do implement Base64, but internal
     * implementation (XSCrypt) is used instead.
     *
     * @returns Pointer to the new Base64 encoder.
     * @see XSCryptCryptoBase64
     */

    virtual XSECCryptoBase64* base64() const;

    //@}

    /** @name Keys and Certificates */
    //@{

    /**
     * \brief Return a DSA key implementation object.
     *
     * Call used by the library to obtain a DSA key object.
     *
     * @returns Pointer to the new DSA key
     * @see NSSCryptoKeyDSA
     */

    virtual XSECCryptoKeyDSA* keyDSA() const;

    /**
     * \brief Return an RSA key implementation object.
     *
     * Call used by the library to obtain an NSS RSA key object.
     *
     * @returns Pointer to the new RSA key
     * @see NSSCryptoKeyRSA
     */

    virtual XSECCryptoKeyRSA* keyRSA() const;

    /**
     * \brief Return an EC key implementation object.
     *
     * Call used by the library to obtain an NSS EC key object.
     *
     * @returns Pointer to the new EC key
     */

    virtual XSECCryptoKeyEC* keyEC() const;

    /**
     * \brief Return a key implementation object based on DER-encoded input.
     *
     * Call used by the library to obtain a key object from a DER-encoded key.
     *
     * @param buf       DER-encoded data
     * @param buflen    length of data
     * @param base64    true iff data is base64-encoded
     * @returns Pointer to the new key
     */

    virtual XSECCryptoKey* keyDER(const char* buf, unsigned long buflen, bool base64) const;

    /**
     * \brief Return an X509 implementation object.
     *
     * Call used by the library to obtain an object that can work
     * with X509 certificates.
     *
     * @returns Pointer to the new X509 object
     * @see NSSCryptoX509
     */

    virtual XSECCryptoX509* X509() const;

    /**
     * \brief Determine whether a given algorithm is supported
     *
     * A call that can be used to determine whether a given
     * symmetric algorithm is supported
     */

    virtual bool algorithmSupported(XSECCryptoSymmetricKey::SymmetricKeyType alg) const;

    /**
     * \brief Return a Symmetric Key implementation object.
     *
     * Call used by the library to obtain a bulk encryption
     * object.
     *
     * @returns Pointer to the new SymmetricKey object
     * @see XSECCryptoSymmetricKey
     */

    virtual XSECCryptoSymmetricKey* keySymmetric(XSECCryptoSymmetricKey::SymmetricKeyType alg) const;

    /**
     * \brief Obtain some random octets
     *
     * For generation of IVs and the like, the library needs to be able
     * to obtain "random" octets.  The library uses this call to the
     * crypto provider to obtain what it needs.
     *
     * @param buffer The buffer to place the random data in
     * @param numOctets Number of bytes required
     * @returns Number of bytes obtained.
     */

    virtual unsigned int getRandom(unsigned char* buffer, unsigned int numOctets) const;

  /**
     * \brief Translate B64 I2OS integer to a NSS SECItem.
     *
     * Decodes a Base64 (ds:CryptoBinary) integer into SECItem.
     *
     * @param b64 Base 64 string
     * @param b64Len Length of base64 string
     * @param retLen Parameter to hold length of return integer
     */

    static SECItem* b642SI(const char* b64, unsigned int b64Len);

  /**
     * \brief Translate a SECItem to a B64 I2OS integer .
     *
     * Encodes a SECItem in I2OSP base64 encoded format.
     *
     * @param n Buffer holding the SECItem
     * @param nLen Length of data in buffer
     * @param retLen Parameter to hold length of return integer
     * @returns A pointer to a buffer holding the encoded data
     * (transfers ownership)
     */

    static unsigned char* SI2b64(SECItem* n, unsigned int &retLen);

    //@}

    /** @name Information Functions */
    //@{

    /**
     * \brief Returns a string that identifies the Crypto Provider
     */

    virtual const XMLCh* getProviderName() const;

    //@}


private:

    void Init(const char * dbDir);
    static int m_initialised;

};

/*\@}*/

#endif /* XSEC_HAVE_NSS */
#endif /* NSSCRYPTOPROVIDER_INCLUDE */


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
 * NSSCryptoKeyRSA := NSS implementation of RSA Keys
 *
 * Author(s): Milan Tomic
 *
 */

#ifndef NSSCRYPTOKEYRSA_INCLUDE
#define NSSCRYPTOKEYRSA_INCLUDE

#include <xsec/enc/XSECCryptoKeyRSA.hpp>

#if defined (XSEC_HAVE_NSS)

#include <pk11func.h>
#include <keyhi.h>
#include <nss.h>

class NSSCryptoProvider;

/**
 * \ingroup nsscrypto
 * @{
 */

/**
 * \brief NSS implementation of the interface class for RSA keys.
 *
 * The library uses classes derived from this to process RSA keys.
 */

class DSIG_EXPORT NSSCryptoKeyRSA : public XSECCryptoKeyRSA {

public :

	/** @name Constructors and Destructors */
	//@{

	/**
	 * \brief Create an RSA key
	 *
	 * @param pubkey A handle to the public key (optional)
	 * @param privkey A handle to the private key (optional)
	 */

	NSSCryptoKeyRSA(SECKEYPublicKey * pubkey = NULL, SECKEYPrivateKey * privkey = NULL);

	virtual ~NSSCryptoKeyRSA();

	//@}

	/** @name Key Interface methods */
	//@{

	/**
	 * \brief Return the type of this key.
	 *
	 * For RSA keys, this allows people to determine whether this is a 
	 * public key, private key or a key pair
	 */

	virtual XSECCryptoKey::KeyType getKeyType() const;

	/**
	 * \brief Return the NSS identifier string
	 */
	
	virtual const XMLCh * getProviderName() const {return DSIGConstants::s_unicodeStrPROVNSS;}
	
	/**
	 * \brief Replicate key
	 */

	virtual XSECCryptoKey * clone() const;

	//@}

	/** @name Mandatory RSA interface methods 
	 *
	 * These classes are required by the library.
	 */
	//@{

	/**
	 * \brief Set the OAEPparams string
	 *
	 * By default, the library expects crypto implementations to perform
	 * OAEP padding with no params. This call allows the library (or user)
	 * to set a params value prior to an encrypt/decrypt operation.
	 *
	 * @param params buffer containing the params data.  Pass in NULL to clear any
	 * old paramters.
	 * @param paramsLen number of bytes in buffer to use.  Pass in 0 to clear any
	 * old parameters.
	 * @note NSS do not support the ability to set OAEP parameters, so this will
	 * throw an XSECCryptoException::UnsupportedError, unless the passed in
	 * paramters are NULL and 0 (to clear).
	 */

	virtual void setOAEPparams(unsigned char * params, unsigned int paramsLen);

	/**
	 * \brief Get OAEPparams Length
	 *
	 * @returns the number of bytes of the OAEPparams buffer (assuming it has been set)
	 * @note NSS do not support the ability to set OAEP parameters, so this will always
   * return 0
	 */

	virtual unsigned int getOAEPparamsLen(void) const;

	/**
	 * \brief Get the OAEPparams
	 *
	 * @returns a pointer to the (crypto object owned) buffer holding the OAEPparams
	 * or NULL if no params are held
	 * @note NSS do not support the ability to set OAEP parameters, so this will always
   * return NULL
	 */

	virtual const unsigned char * getOAEPparams(void) const;

	/**
	 * \brief Set the MGF
	 *
	 * By default, the library expects crypto implementations to perform
	 * OAEP padding with MGF_SHA1.  This call allows the library (or user)
	 * to set a different choice.
	 *
	 * @param mgf the MGF constant identifying the function to use
	 */

	virtual void setMGF(maskGenerationFunc mgf);

	/**
	 * \brief Get the MGF
	 *
	 * @returns the MGF constant in use
	 */

	virtual enum maskGenerationFunc getMGF(void) const;

	/**
	 * \brief Verify a SHA1 PKCS1 encoded signature
	 *
	 * The library will call this function to validate an RSA signature
	 * The standard by default uses SHA1 in a PKCS1 encoding.
	 *
	 * @param hashBuf Buffer containing the pre-calculated (binary) digest
	 * @param hashLen Length of the data in the digest buffer
	 * @param base64Signature Buffer containing the Base64 encoded signature
	 * @param sigLen Length of the data in the signature buffer
	 * @param hm The hash method that was used to create the hash that is being
	 * passed in
	 * @returns true if the signature was valid, false otherwise
	 */

	virtual bool verifySHA1PKCS1Base64Signature(const unsigned char * hashBuf, 
								 unsigned int hashLen,
								 const char * base64Signature,
								 unsigned int sigLen,
								 hashMethod hm);

	/**
	 * \brief Create a signature
	 *
	 * The library will call this function to create a signature from
	 * a pre-calculated digest.  The output signature will
	 * be Base64 encoded such that it can be placed directly into the
	 * XML document
	 *
	 * @param hashBuf Buffer containing the pre-calculated (binary) digest
	 * @param hashLen Number of bytes of hash in the hashBuf
	 * @param base64SignatureBuf Buffer to place the base64 encoded result
	 * in.
	 * @param base64SignatureBufLen Implementations need to ensure they do
	 * not write more bytes than this into the buffer
	 * @param hm Hash Method used in order to embed correct OID for sig
	 */

	virtual unsigned int signSHA1PKCS1Base64Signature(unsigned char * hashBuf,
								unsigned int hashLen,
								char * base64SignatureBuf,
								unsigned int base64SignatureBufLen,
								hashMethod hm);

	/**
	 * \brief Decrypt using private key
	 *
	 * The library will call this function to decrypt a piece of cipher
	 * text using the private component of this key.
	 *
	 * @param inBuf cipher text to decrypt
	 * @param plainBuf output buffer for decrypted bytes
	 * @param inLength bytes of cipher text to decrypt
	 * @param maxOutLength size of outputBuffer
	 * @param padding Type of padding (PKCS 1.5 or OAEP)
	 * @param hm Hash Method for OAEP encryption (OAEPParams should be
	 * set using setOAEPparams()
	 */

	virtual unsigned int privateDecrypt(const unsigned char * inBuf,
								 unsigned char * plainBuf, 
								 unsigned int inLength,
								 unsigned int maxOutLength,
								 PaddingType padding,
								 hashMethod hm);

	/**
	 * \brief Encrypt using a public key
	 *
	 * The library will call this function to encrypt a plain text buffer
	 * using the public component of this key.
	 *
	 * @param inBuf plain text to decrypt
	 * @param cipherBuf output buffer for decrypted bytes
	 * @param inLength bytes of plain text to encrypt
	 * @param maxOutLength size of outputBuffer
	 * @param padding Type of padding (PKCS 1.5 or OAEP)
	 * @param hm Hash Method for OAEP encryption (OAEPParams should be
	 * set using setOAEPparams()
	 */

	virtual unsigned int publicEncrypt(const unsigned char * inBuf,
								 unsigned char * cipherBuf, 
								 unsigned int inLength,
								 unsigned int maxOutLength,
								 PaddingType padding,
								 hashMethod hm);

	/**
	 * \brief Obtain the length of an RSA key
	 *
	 * @returns The length of the rsa key (in bytes)
	 */

	virtual unsigned int getLength(void) const;

	//@}

	/** @name Optional Interface methods
	 * 
	 * Have been implemented to allow interoperability testing
	 */

	//@{

	/**
	 * \brief Load the modulus
	 *
	 * Load the modulus from a Base64 encoded string
	 *
	 * param b64 A buffer containing the encoded string
	 * param len The length of the data in the buffer
	 */

	virtual void loadPublicModulusBase64BigNums(const char * b64, unsigned int len);

	/**
	 * \brief Load the exponent
	 *
	 * Load the exponent from a Base64 encoded string
	 *
	 * param b64 A buffer containing the encoded string
	 * param len The length of the data in the buffer
	 */

	virtual void loadPublicExponentBase64BigNums(const char * b64, unsigned int len);

	//@}

	/** @name NSS Specific Functions */
	//@{


	/**
	 * \brief Retrieve the exponent
	 *
	 * Retrieves the exponent in ds:CryptoBinary encoded format
	 *
	 * @param b64 Buffer to place encoded exponent into
	 * @param len Maximum number of bytes to place in buffer
	 * @returns The number of bytes placed in the buffer
	 */

	unsigned int getExponentBase64BigNums(char * b64, unsigned int len);

	/**
	 * \brief Retrieve the modulus
	 *
	 * Retrieves the modulus in ds:CryptoBinary encoded format
	 *
	 * @param b64 Buffer to place the encoded modulus into
	 * @param len Maximum number of bytes to place in buffer
	 * @returns The number of bytes placed in the buffer
	 */

	unsigned int getModulusBase64BigNums(char * b64, unsigned int len);

	//@}

private:

  SECKEYPublicKey  *	mp_pubkey;
	SECKEYPrivateKey *	mp_privkey;

  SECItem * mp_modulus;
  SECItem * mp_exponent;

	// Instruct to import from parameters

	void importKey(void);
	void loadParamsFromKey(void);

};

#endif /* XSEC_HAVE_NSS */
#endif /* NSSCRYPTOKEYRSA_INCLUDE */

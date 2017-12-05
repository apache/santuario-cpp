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
 * XENCEncryptedTypeImpl := Implementation of the EncryptedType interface
 * element
 *
 * $Id$
 *
 */

#ifndef XENCENCRYPTEDTYPEIMPL_INCLUDE
#define XENCENCRYPTEDTYPEIMPL_INCLUDE

// XSEC Includes

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/xenc/XENCEncryptedType.hpp>
#include <xsec/dsig/DSIGKeyInfoList.hpp>

// Forward declarations

XSEC_DECLARE_XERCES_CLASS(DOMNode);

class XENCCipherDataImpl;
class XENCEncryptionMethodImpl;
class TXFMChain;
class XSECEnv;

class XENCEncryptedTypeImpl : public virtual XENCEncryptedType {

public:

	XENCEncryptedTypeImpl(const XSECEnv * env);
	XENCEncryptedTypeImpl(
		const XSECEnv * env, 
		XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * node
	);

	virtual ~XENCEncryptedTypeImpl();

	// Load elements
	void load();

	// Create from scratch.  LocalName is the name of the owning element

	XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * createBlankEncryptedType(
						XMLCh * localName,
						XENCCipherData::XENCCipherDataType type, 
						const XMLCh * algorithm,
						const XMLCh * value);

	// Interface Methods
	virtual XENCCipherData * getCipherData() const;
	virtual XENCEncryptionMethod * getEncryptionMethod() const;
	virtual void clearKeyInfo();

    /**
    * \brief Get the list of \<KeyInfo\> elements.
    *
    * <p>This function recovers list that contains the KeyInfo elements
    * read in from the DOM document.</p>
    *
    * @returns A pointer to the DSIGKeyInfoList object held by the encrypted type
    */

    virtual DSIGKeyInfoList * getKeyInfoList();

    /**
    * \brief Get the list of \<KeyInfo\> elements.
    *
    * <p>This function recovers list that contains the KeyInfo elements
    * read in from the DOM document.</p>

    * @returns A pointer to the DSIGKeyInfoList object held by the encrypted type
    */

    virtual const DSIGKeyInfoList * getKeyInfoList() const;

	/**
	 * \brief Append a DSA KeyValue element 
	 *
	 * Add a new KeyInfo element for a DSA Value
	 *
	 * @param P Base64 encoded value of P
	 * @param Q Base64 encoded value of Q
	 * @param G Base64 encoded value of G
	 * @param Y Base64 encoded value of Y
	 * @returns A pointer to the created object.
	 */

	virtual DSIGKeyInfoValue * appendDSAKeyValue(const XMLCh * P, 
						   const XMLCh * Q, 
						   const XMLCh * G, 
						   const XMLCh * Y);

	/**
	 * \brief Append a RSA KeyValue element 
	 *
	 * Add a new KeyInfo element for a RSA Value
	 *
	 * @param modulus Base64 encoded value of the modulus
	 * @param exponent Base64 encoded value of exponent
	 * @returns A pointer to the created object.
	 */

	virtual DSIGKeyInfoValue * appendRSAKeyValue(const XMLCh * modulus, 
						   const XMLCh * exponent);

	/**
	 * \brief Append a X509Data element.
	 *
	 * Add a new KeyInfo element for X509 data.
	 *
	 * @note The added element is empty.  The caller must make use of the
	 * returned object to set the required values.
	 *
	 * @returns A pointer to the created object.
	 */

	virtual DSIGKeyInfoX509 * appendX509Data();

    /**
    * \brief Append a KeyName element.
    *
    * Add a new KeyInfo element for a key name.
    *
    * @param name The name of the key to set in the XML
    * @param isDName Treat the name as a Distinguished name and encode accordingly
    * @returns A pointer to the created object
    */

	virtual DSIGKeyInfoName * appendKeyName(const XMLCh * name, bool isDName = false);

    /**
    * \brief Append a PGPData element.
    *
    * Add a new KeyInfo element for a PGP key.
    *
    * @param id The ID of the key to set in the XML (base64 encoded - NULL if none)
    * @param packet The Packet information to set in the XML (base64 encoded -
    * NULL if none)
    * @returns A pointer to the created object
    */

    virtual DSIGKeyInfoPGPData * appendPGPData(const XMLCh * id, const XMLCh * packet);

    /**
    * \brief Append a SPKIData element
    *
    * Add a new KeyInfo element for a set of SPKI S-expressions
    *
    * @param sexp The initial S-expression to set in the SPKIData element
    * @returns A pointer to the created object
    */

    virtual DSIGKeyInfoSPKIData * appendSPKIData(const XMLCh * sexp);

    /**
    * \brief Append a MgmtData element
    *
    * Add a new KeyInfo element for Management Data
    *
    * @param data The string to set in the MgmtData element
    * @returns A pointer to the created object
    */

    virtual DSIGKeyInfoMgmtData * appendMgmtData(const XMLCh * data);

    /**
    * \brief Append an already created EncryptedKey.
    *
    * Add an already created EncryptedKey.
    *
    * @note The encryptedKey becomes the property of the owning EncryptedType
    * object and will be deleted upon its destruction.
    *
    * @param encryptedKey A pointer to the encrypted Key
    */
    
    virtual void appendEncryptedKey(XENCEncryptedKey * encryptedKey);

	// Get methods
	virtual const XMLCh * getType() const;
	virtual const XMLCh * getMimeType() const;
	virtual const XMLCh * getEncoding() const;
	virtual XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * getElement() const
		{return mp_encryptedTypeElement;};

	// Set methods
	virtual void setType(const XMLCh * uri);
	virtual void setMimeType(const XMLCh * mimeType);
	virtual void setEncoding(const XMLCh * uri);

protected:

	// Create the txfm list - gives as output a TXFM chain with
	// the output being the raw encrypted data

	TXFMChain * createCipherTXFMChain();

	// Worker function to start building the KeyInfo list
	void createKeyInfoElement();

	const XSECEnv				* mp_env;
	XERCES_CPP_NAMESPACE_QUALIFIER DOMElement					
								* mp_encryptedTypeElement;	// Node at head of structure
	XERCES_CPP_NAMESPACE_QUALIFIER DOMElement
								* mp_keyInfoElement;		// Any underlying KeyInfo
	XERCES_CPP_NAMESPACE_QUALIFIER DOMNode
								* mp_cipherDataElement;		// CipherData structure
	XENCCipherDataImpl			* mp_cipherData;
	XENCEncryptionMethodImpl	* mp_encryptionMethod;

	// Hold the XML Digital Signature KeyInfo list
	DSIGKeyInfoList			m_keyInfoList;

	// Type URI
	XERCES_CPP_NAMESPACE_QUALIFIER DOMNode
								* mp_typeAttr;
	XERCES_CPP_NAMESPACE_QUALIFIER DOMNode
								* mp_mimeTypeAttr;
	XERCES_CPP_NAMESPACE_QUALIFIER DOMNode
								* mp_encodingAttr;

	friend class XENCCipherImpl;

private:

	// Un-implemented

	XENCEncryptedTypeImpl();
	XENCEncryptedTypeImpl(const XENCEncryptedTypeImpl &);
	XENCEncryptedTypeImpl & operator = (const XENCEncryptedTypeImpl &);
};

#endif /* XENCENCRYPTEDTYPEIMPL_INCLUDE */

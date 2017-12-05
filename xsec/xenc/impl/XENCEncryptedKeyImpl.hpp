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
 * XENCEncryptedKeyImpl := Implementation for holder object for EncryptedKey 
 *
 * $Id$
 *
 */

#ifndef XENCENCRYPTEDKEYIMPL_INCLUDE
#define XENCENCRYPTEDKEYIMPL_INCLUDE

// XSEC Includes

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/xenc/XENCEncryptedKey.hpp>

#include "XENCCipherImpl.hpp"
#include "XENCEncryptedTypeImpl.hpp"

XSEC_DECLARE_XERCES_CLASS(DOMNode);

class XENCEncryptedKeyImpl : public XENCEncryptedKey, public XENCEncryptedTypeImpl {

public:

	XENCEncryptedKeyImpl(const XSECEnv * env);
	XENCEncryptedKeyImpl(
		const XSECEnv * env, 
		XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * node
	);
	virtual ~XENCEncryptedKeyImpl();

	void load();

	// Create a blank EncryptedKey DOM structure

	XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * 
		createBlankEncryptedKey(XENCCipherData::XENCCipherDataType type, 
								 const XMLCh * algorithm,
								 const XMLCh * value);

	// KeyInfo Interface methods
	virtual const XMLCh * getKeyName() const {return NULL;}
	virtual keyInfoType getKeyInfoType() const {return DSIGKeyInfo::KEYINFO_ENCRYPTEDKEY;}

	// EncryptedKey specific Getter Methods
	virtual const XMLCh * getCarriedKeyName() const;
	virtual const XMLCh * getRecipient() const;

	// EncryptedKey specific setter methods
	virtual void setCarriedKeyName(const XMLCh * name);
	virtual void setRecipient(const XMLCh * recipient);


private:

	// Unimplemented
	XENCEncryptedKeyImpl();
	XENCEncryptedKeyImpl(const XENCEncryptedKeyImpl &);
	XENCEncryptedKeyImpl & operator = (const XENCEncryptedKeyImpl &);

	XERCES_CPP_NAMESPACE_QUALIFIER DOMNode
								* mp_carriedKeyNameTextNode;
	XERCES_CPP_NAMESPACE_QUALIFIER DOMNode
								* mp_recipientAttr;

};

#endif /* XENCENCRYPTEDKEYIMPL_INCLUDE */

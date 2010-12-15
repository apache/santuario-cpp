/*
 * Copyright 2003-2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * XSEC
 *
 * XENCEncryptedDataImpl := Implementation for holder object for EncryptedData 
 *
 * $Id$
 *
 */

#ifndef XENCENCRYPTEDDATAIMPL_INCLUDE
#define XENCENCRYPTEDDATAIMPL_INCLUDE

// XSEC Includes

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/xenc/XENCEncryptedData.hpp>

#include "XENCCipherImpl.hpp"
#include "XENCEncryptedTypeImpl.hpp"

XSEC_DECLARE_XERCES_CLASS(DOMNode);

class XENCEncryptedDataImpl : public XENCEncryptedData, public XENCEncryptedTypeImpl {

public:

	XENCEncryptedDataImpl(const XSECEnv * env);
	XENCEncryptedDataImpl(
		const XSECEnv * env, 
		XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * node
	);
	virtual ~XENCEncryptedDataImpl();

	void load(void);

	// Create a blank EncryptedData DOM structure

	XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * 
		createBlankEncryptedData(XENCCipherData::XENCCipherDataType type, 
								 const XMLCh * algorithm,
								 const XMLCh * value);

	// Interface methods

	// Inherited from XENCEncryptedData - need to re-implement
	virtual XENCCipherData * getCipherData(void) const
		{return XENCEncryptedTypeImpl::getCipherData();}
	virtual DSIGKeyInfoList * getKeyInfoList(void)
		{return XENCEncryptedTypeImpl::getKeyInfoList();}
	virtual XENCEncryptionMethod * getEncryptionMethod(void) const
		{return XENCEncryptedTypeImpl::getEncryptionMethod();}
	virtual void clearKeyInfo(void)
		{XENCEncryptedTypeImpl::clearKeyInfo();}
	virtual DSIGKeyInfoValue * appendDSAKeyValue(const XMLCh * P, 
						   const XMLCh * Q, 
						   const XMLCh * G, 
						   const XMLCh * Y)
	    {return XENCEncryptedTypeImpl::appendDSAKeyValue(P, Q, G, Y);}
	virtual DSIGKeyInfoValue * appendRSAKeyValue(const XMLCh * modulus, 
						   const XMLCh * exponent)
	    {return XENCEncryptedTypeImpl::appendRSAKeyValue(modulus, exponent);}
	virtual DSIGKeyInfoX509 * appendX509Data(void)
	    {return XENCEncryptedTypeImpl::appendX509Data();}
	virtual DSIGKeyInfoName * appendKeyName(const XMLCh * name, bool isDName = false)
		{return XENCEncryptedTypeImpl::appendKeyName(name, isDName);}
	virtual XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * getElement(void) const
		{return XENCEncryptedTypeImpl::getElement();}
	virtual void appendEncryptedKey(XENCEncryptedKey * encryptedKey)
		{XENCEncryptedTypeImpl::appendEncryptedKey(encryptedKey);}

	// Get methods
	virtual const XMLCh * getType(void) const
		{return XENCEncryptedTypeImpl::getType();}
	virtual const XMLCh * getMimeType(void) const
		{return XENCEncryptedTypeImpl::getMimeType();}
	virtual const XMLCh * getEncoding(void) const
		{return XENCEncryptedTypeImpl::getEncoding();}

	// Set methods
	virtual void setType(const XMLCh * uri)
		{XENCEncryptedTypeImpl::setType(uri);}
	virtual void setMimeType(const XMLCh * mimeType)
		{XENCEncryptedTypeImpl::setMimeType(mimeType);}
	virtual void setEncoding(const XMLCh * uri)
		{XENCEncryptedTypeImpl::setEncoding(uri);}

private:

	// Unimplemented
	XENCEncryptedDataImpl(void);
	XENCEncryptedDataImpl(const XENCEncryptedDataImpl &);
	XENCEncryptedDataImpl & operator = (const XENCEncryptedDataImpl &);

};

#endif /* XENCENCRYPTEDDATAIMPL_INCLUDE */

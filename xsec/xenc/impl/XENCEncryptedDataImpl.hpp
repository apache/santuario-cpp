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

	void load();

	// Create a blank EncryptedData DOM structure

	XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * 
		createBlankEncryptedData(XENCCipherData::XENCCipherDataType type, 
								 const XMLCh * algorithm,
								 const XMLCh * value);

private:

	// Unimplemented
	XENCEncryptedDataImpl();
	XENCEncryptedDataImpl(const XENCEncryptedDataImpl &);
	XENCEncryptedDataImpl & operator = (const XENCEncryptedDataImpl &);

};

#endif /* XENCENCRYPTEDDATAIMPL_INCLUDE */

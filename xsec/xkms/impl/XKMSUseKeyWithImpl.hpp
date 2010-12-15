/*
 * Copyright 2004-2005 The Apache Software Foundation.
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
 * XKMSUseKeyWithImpl := Implementation of UseKeyWith Messages
 *
 * $Id$
 *
 */

#ifndef XKMSUSEKEYWITHIMPL_INCLUDE
#define XKMSUSEKEYWITHIMPL_INCLUDE

// XSEC Includes

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/xkms/XKMSUseKeyWith.hpp>

class XKMSUseKeyWithImpl : public XKMSUseKeyWith {

public:

	XKMSUseKeyWithImpl(
		const XSECEnv * env
	);

	XKMSUseKeyWithImpl(
		const XSECEnv * env, 
		XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * node
	);

	virtual ~XKMSUseKeyWithImpl() ;

	// Load
	void load(void);

	// Create
	XERCES_CPP_NAMESPACE_QUALIFIER DOMElement *
		createBlankUseKeyWith(
			const XMLCh * application,  
			const XMLCh * identifier);


	// Interface methods

	virtual XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * getElement(void) const;
	virtual const XMLCh * getApplication(void) const;
	virtual const XMLCh * getIdentifier(void) const;
	virtual void setApplication(const XMLCh * uri);
	virtual void setIdentifier(const XMLCh * identifier);

protected:

	XERCES_CPP_NAMESPACE_QUALIFIER DOMElement
					* mp_useKeyWithElement;
	const XSECEnv	* mp_env;

private:

	XERCES_CPP_NAMESPACE_QUALIFIER DOMNode
					* mp_applicationAttr;
	XERCES_CPP_NAMESPACE_QUALIFIER DOMNode
					* mp_identifierAttr;

	// Unimplemented
	XKMSUseKeyWithImpl(const XKMSUseKeyWithImpl &);
	XKMSUseKeyWithImpl & operator = (const XKMSUseKeyWithImpl &);

};

#endif /* XKMSUSEKEYWITHIMPL_INCLUDE */

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
 * XKMSReissueKeyBindingImpl := Implementation for ReissueKeyBinding
 *
 * $Id$
 *
 */

// XSEC Includes

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/framework/XSECError.hpp>
#include <xsec/framework/XSECEnv.hpp>


#ifdef XSEC_XKMS_ENABLED

#include "XKMSReissueKeyBindingImpl.hpp"
#include "XKMSStatusImpl.hpp"

#include <xsec/xkms/XKMSConstants.hpp>

#include <xercesc/dom/DOM.hpp>

XERCES_CPP_NAMESPACE_USE

// --------------------------------------------------------------------------------
//           Construct/Destruct
// --------------------------------------------------------------------------------

XKMSReissueKeyBindingImpl::XKMSReissueKeyBindingImpl(
		const XSECEnv * env 
		) :
XKMSKeyBindingAbstractTypeImpl(env) {
	mp_status = NULL;
}

XKMSReissueKeyBindingImpl::XKMSReissueKeyBindingImpl(
		const XSECEnv * env, 
		XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * node
		) :
XKMSKeyBindingAbstractTypeImpl(env, node) {

	mp_status = NULL;
}

XKMSReissueKeyBindingImpl::~XKMSReissueKeyBindingImpl() {

	if (mp_status != NULL)
		delete mp_status;

}

// --------------------------------------------------------------------------------
//           Load from DOM
// --------------------------------------------------------------------------------

void XKMSReissueKeyBindingImpl::load(void) {

	if (mp_keyBindingAbstractTypeElement == NULL) {
		throw XSECException(XSECException::ExpectedXKMSChildNotFound,
			"XKMSReissueKeyBindingImpl::load - called on empty DOM");
	}

	XKMSKeyBindingAbstractTypeImpl::load();

	/* Find the status element */
	DOMNodeList * nl = mp_keyBindingAbstractTypeElement->getElementsByTagNameNS(
		XKMSConstants::s_unicodeStrURIXKMS,
		XKMSConstants::s_tagStatus);

	if (nl == NULL || nl->getLength() != 1) {
		throw XSECException(XSECException::ExpectedXKMSChildNotFound,
			"XKMSReissueKeyBinding::load - Status value not found");
	}

	XSECnew(mp_status, XKMSStatusImpl(mp_env, (DOMElement*) nl->item(0)));
	mp_status->load();

}

// --------------------------------------------------------------------------------
//           Create
// --------------------------------------------------------------------------------

DOMElement * XKMSReissueKeyBindingImpl::createBlankReissueKeyBinding(XKMSStatus::StatusValue status) {

	DOMElement * ret = XKMSKeyBindingAbstractTypeImpl::
				createBlankKeyBindingAbstractType(XKMSConstants::s_tagReissueKeyBinding);

	mp_env->doPrettyPrint(ret);

	// Create the status element
	XSECnew(mp_status, XKMSStatusImpl(mp_env));
	ret->appendChild(mp_status->createBlankStatus(status));
	mp_env->doPrettyPrint(ret);

	// Must have an Id
	XKMSKeyBindingAbstractTypeImpl::setId();

	return ret;

}

// --------------------------------------------------------------------------------
//           Status handling
// --------------------------------------------------------------------------------

XKMSStatus * XKMSReissueKeyBindingImpl::getStatus(void) const {

	return mp_status;

}

#endif /* XSEC_XKMS_ENABLED */

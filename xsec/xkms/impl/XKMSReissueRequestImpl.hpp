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
 * XKMSReissueRequestImpl := Implementation for ReissueRequest Messages
 *
 * $Id$
 *
 */

#ifndef XKMSREISSUEREQUESTIMPL_INCLUDE
#define XKMSREISSUEREQUESTIMPL_INCLUDE

// XSEC Includes

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/xkms/XKMSReissueRequest.hpp>

#ifdef XSEC_XKMS_ENABLED

#include "XKMSRequestAbstractTypeImpl.hpp"

class XKMSAuthenticationImpl;
class XKMSReissueKeyBindingImpl;
class DSIGSignature;

class XKMSReissueRequestImpl : public XKMSReissueRequest {

public: 
	XKMSRequestAbstractTypeImpl m_request;
	XKMSMessageAbstractTypeImpl &m_msg;
public:

	XKMSReissueRequestImpl(
		const XSECEnv * env
	);

	XKMSReissueRequestImpl(
		const XSECEnv * env, 
		XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * node
	);

	virtual ~XKMSReissueRequestImpl();

	// Load elements
	void load();

	// Creation
	XERCES_CPP_NAMESPACE_QUALIFIER DOMElement * 
		createBlankReissueRequest(
		const XMLCh * service,
		const XMLCh * id = NULL);


	/* Getter Interface Methods */
	virtual XKMSReissueKeyBinding * getReissueKeyBinding(void) const;
	virtual XKMSAuthentication * getAuthentication (void) const;
	virtual DSIGSignature * getProofOfPossessionSignature(void) const;

	/* Setter Interface Methods */

	virtual XKMSReissueKeyBinding * addReissueKeyBinding(XKMSStatus::StatusValue status);
	virtual XKMSAuthentication * addAuthentication(void);
	virtual DSIGSignature * addProofOfPossessionSignature(
		const XMLCh* c14nAlgorithm,
                const XMLCh* signatureAlgorithm,
                const XMLCh* hashAlgorithm);

	/* Implemented from MessageAbstractType */
	virtual messageType getMessageType(void);

	/* Forced inheritance from XKMSMessageAbstractTypeImpl */
	XKMS_MESSAGEABSTRACTYPE_IMPL_METHODS

	/* Forced inheritance from RequestAbstractType */
	XKMS_REQUESTABSTRACTYPE_IMPL_METHODS


private:

	XKMSAuthenticationImpl		* mp_authentication;
	XKMSReissueKeyBindingImpl	* mp_reissueKeyBinding;
	DSIGSignature				* mp_proofOfPossessionSignature;

	XSECProvider				m_prov;		// For creating the signature

	// Unimplemented
	XKMSReissueRequestImpl(void);
	XKMSReissueRequestImpl(const XKMSReissueRequestImpl &);
	XKMSReissueRequestImpl & operator = (const XKMSReissueRequestImpl &);

};

#endif /* XSEC_XKMS_ENABLED */
#endif /* XKMSREISSUEREQUESTIMPL_INCLUDE */

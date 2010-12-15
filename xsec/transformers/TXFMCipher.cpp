/*
 * Copyright 2002-2005 The Apache Software Foundation.
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
 * TXFMCipher := Class that performs encryption and decryption transforms
 *
 * $Id$
 *
 */

// XSEC

#include <xsec/framework/XSECDefs.hpp>
#include <xsec/transformers/TXFMCipher.hpp>
#include <xsec/utils/XSECPlatformUtils.hpp>
#include <xsec/framework/XSECException.hpp>

XERCES_CPP_NAMESPACE_USE

TXFMCipher::TXFMCipher(DOMDocument *doc, 
					   XSECCryptoKey * key, 
					   bool encrypt) : 
TXFMBase(doc),
m_doEncrypt(encrypt),
m_remaining(0) {


	mp_cipher = key->clone();
	
	if (!mp_cipher) {

		throw XSECException(XSECException::CryptoProviderError, 
				"Error cloning key");

	}

	m_complete = false;

	try {
		if (mp_cipher->getKeyType() == XSECCryptoKey::KEY_SYMMETRIC && m_doEncrypt)
			((XSECCryptoSymmetricKey *) (mp_cipher))->encryptInit();
		else
			((XSECCryptoSymmetricKey *) (mp_cipher))->decryptInit();
	}
	catch (...) {
		delete mp_cipher;
		mp_cipher = NULL;
		throw;
	}

};

TXFMCipher::~TXFMCipher() {

	if (mp_cipher != NULL)
		delete mp_cipher;

};

	// Methods to set the inputs

void TXFMCipher::setInput(TXFMBase *newInput) {

	input = newInput;

	// Set up for comments
	keepComments = input->getCommentsStatus();

}

	// Methods to get tranform output type and input requirement

TXFMBase::ioType TXFMCipher::getInputType(void) {

	return TXFMBase::BYTE_STREAM;

}
TXFMBase::ioType TXFMCipher::getOutputType(void) {

	return TXFMBase::BYTE_STREAM;

}


TXFMBase::nodeType TXFMCipher::getNodeType(void) {

	return TXFMBase::DOM_NODE_NONE;

}

// Methods to get output data

unsigned int TXFMCipher::readBytes(XMLByte * const toFill, unsigned int maxToFill) {
	
	unsigned int ret, fill, leftToFill;

	ret = 0;					// How much have we copied?
	leftToFill = maxToFill;		// Still have to copy in entire thing

	while (ret != maxToFill && (m_complete == false || m_remaining > 0)) {
	
		if (m_remaining != 0) {

			// Copy anything remaining in the buffer to the output

			fill = (leftToFill > m_remaining ? m_remaining : leftToFill);
			memcpy(&toFill[ret], m_outputBuffer, fill);

			if (fill < m_remaining)
				memmove(m_outputBuffer, m_outputBuffer + fill, (m_remaining - fill));

			m_remaining -= fill;
			leftToFill -= fill;
			ret += fill;
		}

		// Now do some crypting

		if (m_complete == false && m_remaining == 0) {

			unsigned int sz = input->readBytes(m_inputBuffer, 2048);
		
			if (mp_cipher->getKeyType() == XSECCryptoKey::KEY_SYMMETRIC) {
				XSECCryptoSymmetricKey * symCipher = 
					(XSECCryptoSymmetricKey*) mp_cipher;
				if (m_doEncrypt) {
					
					if (sz == 0) {
						m_complete = true;
						m_remaining = symCipher->encryptFinish(m_outputBuffer, 3072);
					}
					else
						m_remaining = symCipher->encrypt(m_inputBuffer, m_outputBuffer, sz, 3072);
				}
				else {

					if (sz == 0) {
						m_complete = true;
						m_remaining = symCipher->decryptFinish(m_outputBuffer, 3072);
					}
					else
						m_remaining = symCipher->decrypt(m_inputBuffer, m_outputBuffer, sz, 3072);
				}
			}
		}

	}

	return ret;

}

DOMDocument *TXFMCipher::getDocument() {

	return NULL;

}

DOMNode * TXFMCipher::getFragmentNode() {

	return NULL;		// Return a null node

}

const XMLCh * TXFMCipher::getFragmentId() {

	return NULL;	// Empty string

}

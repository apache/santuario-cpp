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
 * DSIGConstants := Definitions of various DSIG constants (mainly strings)
 *
 * Author(s): Berin Lautenbach
 *
 * $Id$
 *
 */

#ifndef DSIGCONSTANTS_HEADER
#define DSIGCONSTANTS_HEADER

#include <xsec/enc/XSECCryptoHash.hpp>
#include <xsec/utils/XSECSafeBuffer.hpp>

// Xerces
#include <xercesc/util/XMLString.hpp>

XSEC_USING_XERCES(XMLString);

// Name Spaces

#define URI_ID_DSIG		"http://www.w3.org/2000/09/xmldsig#"
#define URI_ID_DSIG11	"http://www.w3.org/2009/xmldsig11#"
#define URI_ID_EC		"http://www.w3.org/2001/10/xml-exc-c14n#"
// Also used as algorithm ID for XPATH_FILTER
#define URI_ID_XPF		"http://www.w3.org/2002/06/xmldsig-filter2"
#define URI_ID_XENC		"http://www.w3.org/2001/04/xmlenc#"
#define URI_ID_XENC11	"http://www.w3.org/2009/xmlenc11#"

// Hashing Algorithms

#define URI_ID_SHA1			"http://www.w3.org/2000/09/xmldsig#sha1"
#define URI_ID_MD5			"http://www.w3.org/2001/04/xmldsig-more#md5"
#define URI_ID_SHA224       "http://www.w3.org/2001/04/xmldsig-more#sha224"
#define URI_ID_SHA256       "http://www.w3.org/2001/04/xmlenc#sha256"
#define URI_ID_SHA384       "http://www.w3.org/2001/04/xmldsig-more#sha384"
#define URI_ID_SHA512       "http://www.w3.org/2001/04/xmlenc#sha512"

// Encryption Algorithms
#define URI_ID_3DES_CBC		"http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
#define URI_ID_AES128_CBC	"http://www.w3.org/2001/04/xmlenc#aes128-cbc"
#define URI_ID_AES192_CBC	"http://www.w3.org/2001/04/xmlenc#aes192-cbc"
#define URI_ID_AES256_CBC	"http://www.w3.org/2001/04/xmlenc#aes256-cbc"
#define URI_ID_AES128_GCM	"http://www.w3.org/2009/xmlenc11#aes128-gcm"
#define URI_ID_AES192_GCM	"http://www.w3.org/2009/xmlenc11#aes192-gcm"
#define URI_ID_AES256_GCM	"http://www.w3.org/2009/xmlenc11#aes256-gcm"


// Key Wrap Algorithm
#define URI_ID_KW_3DES		    "http://www.w3.org/2001/04/xmlenc#kw-tripledes"
#define URI_ID_KW_AES128	    "http://www.w3.org/2001/04/xmlenc#kw-aes128"
#define URI_ID_KW_AES192	    "http://www.w3.org/2001/04/xmlenc#kw-aes192"
#define URI_ID_KW_AES256	    "http://www.w3.org/2001/04/xmlenc#kw-aes256"
#define URI_ID_KW_AES128_PAD	"http://www.w3.org/2009/xmlenc11#kw-aes-128-pad"
#define URI_ID_KW_AES192_PAD	"http://www.w3.org/2009/xmlenc11#kw-aes-192-pad"
#define URI_ID_KW_AES256_PAD	"http://www.w3.org/2009/xmlenc11#kw-aes-256-pad"

// Key Transport algorithms
#define URI_ID_RSA_1_5			"http://www.w3.org/2001/04/xmlenc#rsa-1_5"
#define URI_ID_RSA_OAEP_MGFP1	"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
#define URI_ID_RSA_OAEP	        "http://www.w3.org/2009/xmlenc11#rsa-oaep"

// OAEP MGFs
#define URI_ID_MGF1_BASE	    "http://www.w3.org/2009/xmlenc11#mgf1"
#define URI_ID_MGF1_SHA1        "http://www.w3.org/2009/xmlenc11#mgf1sha1"
#define URI_ID_MGF1_SHA224      "http://www.w3.org/2009/xmlenc11#mgf1sha224"
#define URI_ID_MGF1_SHA256      "http://www.w3.org/2009/xmlenc11#mgf1sha256"
#define URI_ID_MGF1_SHA384      "http://www.w3.org/2009/xmlenc11#mgf1sha384"
#define URI_ID_MGF1_SHA512      "http://www.w3.org/2009/xmlenc11#mgf1sha512"

// Transforms

#define URI_ID_BASE64			"http://www.w3.org/2000/09/xmldsig#base64"
#define URI_ID_XPATH			"http://www.w3.org/TR/1999/REC-xpath-19991116"
#define URI_ID_XSLT				"http://www.w3.org/TR/1999/REC-xslt-19991116"
#define URI_ID_ENVELOPE			"http://www.w3.org/2000/09/xmldsig#enveloped-signature"
#define URI_ID_C14N_NOC			"http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
#define URI_ID_C14N_COM			"http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
#define URI_ID_C14N11_NOC       "http://www.w3.org/2006/12/xml-c14n11"
#define URI_ID_C14N11_COM       "http://www.w3.org/2006/12/xml-c14n11#WithComments"
#define URI_ID_EXC_C14N_NOC		"http://www.w3.org/2001/10/xml-exc-c14n#"
#define URI_ID_EXC_C14N_COM		"http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
#define XPATH_EXPR_ENVELOPE		"count(ancestor-or-self::dsig:Signature | \
								 here()/ancestor::dsig:Signature[1]) > \
								 count(ancestor-or-self::dsig:Signature)"

// Signature Algorithms

#define URI_ID_SIG_BASE		"http://www.w3.org/2000/09/xmldsig#"
#define URI_ID_SIG_BASEMORE	"http://www.w3.org/2001/04/xmldsig-more#"
#define URI_ID_SIG_BASE11	"http://www.w3.org/2009/xmldsig11#"
#define URI_ID_SIG_DSA		"dsa"
#define URI_ID_SIG_ECDSA	"ecdsa"
#define URI_ID_SIG_HMAC		"hmac"
#define URI_ID_SIG_SHA1		"sha1"
#define URI_ID_SIG_SHA224	"sha224"
#define URI_ID_SIG_SHA256	"sha256"
#define URI_ID_SIG_SHA384	"sha384"
#define URI_ID_SIG_SHA512	"sha512"
#define URI_ID_SIG_RSA		"rsa"
#define URI_ID_SIG_MD5		"md5"

#define URI_ID_DSA_SHA1		"http://www.w3.org/2000/09/xmldsig#dsa-sha1"
#define URI_ID_DSA_SHA256	"http://www.w3.org/2009/xmldsig11#dsa-sha256"
#define URI_ID_HMAC_SHA1	"http://www.w3.org/2000/09/xmldsig#hmac-sha1"
#define URI_ID_HMAC_SHA224	"http://www.w3.org/2001/04/xmldsig-more#hmac-sha224"
#define URI_ID_HMAC_SHA256	"http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
#define URI_ID_HMAC_SHA384	"http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"
#define URI_ID_HMAC_SHA512	"http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
#define URI_ID_RSA_SHA1		"http://www.w3.org/2000/09/xmldsig#rsa-sha1"
#define URI_ID_RSA_SHA224	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha224"
#define URI_ID_RSA_SHA256	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
#define URI_ID_RSA_SHA384	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
#define URI_ID_RSA_SHA512	"http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
#define URI_ID_RSA_MD5		"http://www.w3.org/2001/04/xmldsig-more#rsa-md5"
#define URI_ID_ECDSA_SHA1	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
#define URI_ID_ECDSA_SHA224	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha224"
#define URI_ID_ECDSA_SHA256	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
#define URI_ID_ECDSA_SHA384	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
#define URI_ID_ECDSA_SHA512	"http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

// Encryption defines
#define URI_ID_XENC_ELEMENT	"http://www.w3.org/2001/04/xmlenc#Element"
#define URI_ID_XENC_CONTENT	"http://www.w3.org/2001/04/xmlenc#Content"

// General

#define URI_ID_XMLNS	"http://www.w3.org/2000/xmlns/"
#define URI_ID_MANIFEST "http://www.w3.org/2000/09/xmldsig#Manifest"
#define URI_ID_RAWX509  "http://www.w3.org/2000/09/xmldsig#rawX509Certificate"

// Internal Crypto Providers

#define PROV_OPENSSL	"OpenSSL Provider"
#define PROV_WINCAPI	"WinCAPI Provider"
#define PROV_NSS	    "NSS Provider"

// Enumerated Types

enum canonicalizationMethod {

	CANON_NONE					= 0,			// No method defined
	CANON_C14N_NOC				= 1,			// C14n without comments
	CANON_C14N_COM				= 2, 			// C14n with comments
	CANON_C14NE_NOC				= 3,			// C14n Exclusive (without comments)
	CANON_C14NE_COM				= 4,			// C14n Exlusive (with Comments
	CANON_C14N11_NOC            = 5,            // C14n 1.1 without comments
	CANON_C14N11_COM            = 6             // C14n 1.1 with comments
};

enum signatureMethod {

	SIGNATURE_NONE				= 0,			// No method defined
	SIGNATURE_DSA				= 1, 			// DSA
	SIGNATURE_HMAC				= 2,			// Hash MAC
	SIGNATURE_RSA				= 3,			// RSA
	SIGNATURE_ECDSA				= 4				// ECDSA
};


enum transformType {

	TRANSFORM_BASE64,
	TRANSFORM_C14N,
    TRANSFORM_C14N11,
	TRANSFORM_EXC_C14N,
	TRANSFORM_ENVELOPED_SIGNATURE,
	TRANSFORM_XPATH,
	TRANSFORM_XSLT,
	TRANSFORM_XPATH_FILTER
};

enum xpathFilterType {

	FILTER_UNION			= 0,	/** Results should be added to previous nodeset */
	FILTER_INTERSECT		= 1,	/** Results should be included if in prev nodeset */
	FILTER_SUBTRACT			= 2		/** Results should be subtracted from prev nodeset */

};

// --------------------------------------------------------------------------------
//           Some utility functions
// --------------------------------------------------------------------------------

inline
bool canonicalizationMethod2URI(safeBuffer& uri, canonicalizationMethod cm) {

	switch (cm) {

	case (CANON_C14N_NOC) :

		uri = URI_ID_C14N_NOC;
		break;

	case (CANON_C14N_COM) :

		uri = URI_ID_C14N_COM;
		break;

	case (CANON_C14NE_NOC) :

		uri = URI_ID_EXC_C14N_NOC;
		break;

	case (CANON_C14NE_COM) :

		uri = URI_ID_EXC_C14N_COM;
		break;

    case (CANON_C14N11_NOC) :

        uri = URI_ID_C14N11_NOC;
        break;

    case (CANON_C14N11_COM) :

        uri = URI_ID_C14N11_COM;
        break;

	default :
		return false;		// Unknown type

	}

	return true;

}

// --------------------------------------------------------------------------------
//           Constant Strings Class
// --------------------------------------------------------------------------------

class XSEC_EXPORT DSIGConstants {

public:

	// General strings

	static const XMLCh * s_unicodeStrEmpty;		// ""
	static const XMLCh * s_unicodeStrNL;		// "\n"
	static const XMLCh * s_unicodeStrXmlns;		// "xmlns"
	static const XMLCh * s_unicodeStrURI;		// "URI"

	// DSIG Element Strings
	static const XMLCh * s_unicodeStrAlgorithm;

	// URI_IDs
	static const XMLCh * s_unicodeStrURIDSIG;
    static const XMLCh * s_unicodeStrURIDSIG11;
	static const XMLCh * s_unicodeStrURIEC;
	static const XMLCh * s_unicodeStrURIXPF;
	static const XMLCh * s_unicodeStrURIXENC;
    static const XMLCh * s_unicodeStrURIXENC11;

	static const XMLCh * s_unicodeStrURISIGBASE;
	static const XMLCh * s_unicodeStrURISIGBASEMORE;
    static const XMLCh * s_unicodeStrURISIGBASE11;

	static const XMLCh * s_unicodeStrURIRawX509;
	static const XMLCh * s_unicodeStrURISHA1;
	static const XMLCh * s_unicodeStrURISHA224;
	static const XMLCh * s_unicodeStrURISHA256;
	static const XMLCh * s_unicodeStrURISHA384;
	static const XMLCh * s_unicodeStrURISHA512;
	static const XMLCh * s_unicodeStrURIMD5;		// Not recommended
	static const XMLCh * s_unicodeStrURIBASE64;
	static const XMLCh * s_unicodeStrURIXPATH;
	static const XMLCh * s_unicodeStrURIXSLT;
	static const XMLCh * s_unicodeStrURIENVELOPE;
	static const XMLCh * s_unicodeStrURIC14N_NOC;
	static const XMLCh * s_unicodeStrURIC14N_COM;
    static const XMLCh * s_unicodeStrURIC14N11_NOC;
    static const XMLCh * s_unicodeStrURIC14N11_COM;
	static const XMLCh * s_unicodeStrURIEXC_C14N_NOC;
	static const XMLCh * s_unicodeStrURIEXC_C14N_COM;

	static const XMLCh * s_unicodeStrURIDSA_SHA1;
    static const XMLCh * s_unicodeStrURIDSA_SHA256;

	static const XMLCh * s_unicodeStrURIRSA_MD5;
	static const XMLCh * s_unicodeStrURIRSA_SHA1;
	static const XMLCh * s_unicodeStrURIRSA_SHA224;
	static const XMLCh * s_unicodeStrURIRSA_SHA256;
	static const XMLCh * s_unicodeStrURIRSA_SHA384;
	static const XMLCh * s_unicodeStrURIRSA_SHA512;

	static const XMLCh * s_unicodeStrURIECDSA_SHA1;
    static const XMLCh * s_unicodeStrURIECDSA_SHA224;
	static const XMLCh * s_unicodeStrURIECDSA_SHA256;
	static const XMLCh * s_unicodeStrURIECDSA_SHA384;
	static const XMLCh * s_unicodeStrURIECDSA_SHA512;

	static const XMLCh * s_unicodeStrURIHMAC_SHA1;
	static const XMLCh * s_unicodeStrURIHMAC_SHA224;
	static const XMLCh * s_unicodeStrURIHMAC_SHA256;
	static const XMLCh * s_unicodeStrURIHMAC_SHA384;
	static const XMLCh * s_unicodeStrURIHMAC_SHA512;

	static const XMLCh * s_unicodeStrURIXMLNS;
	static const XMLCh * s_unicodeStrURIMANIFEST;

	// URIs for Encryption
	static const XMLCh * s_unicodeStrURI3DES_CBC;
	static const XMLCh * s_unicodeStrURIAES128_CBC;
	static const XMLCh * s_unicodeStrURIAES192_CBC;
	static const XMLCh * s_unicodeStrURIAES256_CBC;
	static const XMLCh * s_unicodeStrURIAES128_GCM;
    static const XMLCh * s_unicodeStrURIAES192_GCM;
	static const XMLCh * s_unicodeStrURIAES256_GCM;
	static const XMLCh * s_unicodeStrURIKW_3DES;
	static const XMLCh * s_unicodeStrURIKW_AES128;
	static const XMLCh * s_unicodeStrURIKW_AES192;
	static const XMLCh * s_unicodeStrURIKW_AES256;
	static const XMLCh * s_unicodeStrURIKW_AES128_PAD;
	static const XMLCh * s_unicodeStrURIKW_AES192_PAD;
	static const XMLCh * s_unicodeStrURIKW_AES256_PAD;
	static const XMLCh * s_unicodeStrURIRSA_1_5;
	static const XMLCh * s_unicodeStrURIRSA_OAEP_MGFP1;
    static const XMLCh * s_unicodeStrURIRSA_OAEP;

    static const XMLCh * s_unicodeStrURIMGF1_BASE;
	static const XMLCh * s_unicodeStrURIMGF1_SHA1;
	static const XMLCh * s_unicodeStrURIMGF1_SHA224;
	static const XMLCh * s_unicodeStrURIMGF1_SHA256;
	static const XMLCh * s_unicodeStrURIMGF1_SHA384;
	static const XMLCh * s_unicodeStrURIMGF1_SHA512;
   
	static const XMLCh * s_unicodeStrURIXENC_ELEMENT;
	static const XMLCh * s_unicodeStrURIXENC_CONTENT;

	// Internal Crypto Providers
	static const XMLCh * s_unicodeStrPROVOpenSSL;
	static const XMLCh * s_unicodeStrPROVWinCAPI;
    static const XMLCh * s_unicodeStrPROVNSS;


	DSIGConstants();

	static void create();
	static void destroy();

};




inline
const XMLCh* canonicalizationMethod2UNICODEURI(canonicalizationMethod cm) {

	switch (cm) {

	case (CANON_C14N_NOC) :

		return DSIGConstants::s_unicodeStrURIC14N_NOC;

	case (CANON_C14N_COM) :

		return DSIGConstants::s_unicodeStrURIC14N_COM;

	case (CANON_C14NE_NOC) :

		return DSIGConstants::s_unicodeStrURIEXC_C14N_NOC;

	case (CANON_C14NE_COM) :

		return DSIGConstants::s_unicodeStrURIEXC_C14N_COM;

	default :
		break;

	}

	return DSIGConstants::s_unicodeStrEmpty;

}

// --------------------------------------------------------------------------------
//			URI Inverse Mappings
// --------------------------------------------------------------------------------

/* Map URIs to internal enums, if the URIs are known to the library.
   If they aren't, all these calls will set the Method variables to
   *_NONE, signifying we don't know them.  Note this is not necessarily
   an error - the calling application may have installed handlers to handle
   these URIs, it's just we don't have an internal enum mapping
*/

bool XSEC_EXPORT XSECmapURIToSignatureMethods(const XMLCh* URI,
												  signatureMethod& sm,
												  XSECCryptoHash::HashType& type);
bool XSEC_EXPORT XSECmapURIToHashType(const XMLCh* URI, XSECCryptoHash::HashType& type);
bool XSEC_EXPORT XSECmapURIToCanonicalizationMethod(const XMLCh* URI,
							canonicalizationMethod& cm);

#endif /* DSIGCONSTANTS_HEADER */

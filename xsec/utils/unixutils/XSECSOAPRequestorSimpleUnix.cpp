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
 * XSECSOAPRequestorSimple := (Very) Basic implementation of a SOAP
 *                         HTTP wrapper for testing the client code.
 *
 *
 * $Id$
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

#include <string>
#include <sstream>

#include <xsec/utils/XSECSOAPRequestorSimple.hpp>
#include <xsec/utils/XSECSafeBuffer.hpp>
#include <xsec/framework/XSECError.hpp>

#include "../../utils/XSECAutoPtr.hpp"

#include <xercesc/dom/DOM.hpp>
#include <xercesc/util/XMLNetAccessor.hpp>
#include <xercesc/util/XMLString.hpp>
#include <xercesc/util/XMLExceptMsgs.hpp>
#include <xercesc/util/Janitor.hpp>
#include <xercesc/util/XMLUniDefs.hpp>

XERCES_CPP_NAMESPACE_USE
using std::string;
using std::ostringstream;

// --------------------------------------------------------------------------------
//           Platform specific constructor
// --------------------------------------------------------------------------------


XSECSOAPRequestorSimple::XSECSOAPRequestorSimple(const XMLCh * uri) : m_uri(uri), m_envelopeType(ENVELOPE_NONE) {


}

// --------------------------------------------------------------------------------
//           Interface
// --------------------------------------------------------------------------------


DOMDocument * XSECSOAPRequestorSimple::doRequest(DOMDocument * request) {


    char* content = wrapAndSerialise(request);

    // First we need to serialise

    //
    // Pull all of the parts of the URL out of th m_uri object, and transcode them
    //   and transcode them back to ASCII.
    //
    const XMLCh*        hostName = m_uri.getHost();
    XSECAutoPtrChar     hostNameAsCharStar(hostName);

    const XMLCh*        path = m_uri.getPath();
    XSECAutoPtrChar     pathAsCharStar(path);

    const XMLCh*        fragment = m_uri.getFragment();
    XSECAutoPtrChar     fragmentAsCharStar(fragment);

    const XMLCh*        query = m_uri.getQueryString();
    XSECAutoPtrChar     queryAsCharStar(query);

    unsigned short      portNumber = (unsigned short) m_uri.getPort();

    // If no number is set, go with port 80
    if (portNumber == USHRT_MAX)
        portNumber = 80;

    //
    // Set up a socket.
    //
    struct hostent*     hostEntPtr = 0;
    struct sockaddr_in  sa;


    if ((hostEntPtr = gethostbyname(hostNameAsCharStar.get())) == NULL)
    {
        unsigned long  numAddress = inet_addr(hostNameAsCharStar.get());
        if (numAddress == 0)
        {
            ThrowXML(NetAccessorException,
                     XMLExcepts::NetAcc_TargetResolution);
        }
        if ((hostEntPtr =
                gethostbyaddr((char *) &numAddress,
                              sizeof(unsigned long), AF_INET)) == NULL)
        {
            ThrowXML(NetAccessorException,
                     XMLExcepts::NetAcc_TargetResolution);
        }
    }

    memcpy((void *) &sa.sin_addr,
           (const void *) hostEntPtr->h_addr, hostEntPtr->h_length);
    sa.sin_family = hostEntPtr->h_addrtype;
    sa.sin_port = htons(portNumber);

    int s = socket(hostEntPtr->h_addrtype, SOCK_STREAM, 0);
    if (s < 0)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
                            "Error creating socket");
    }

    if (connect(s, (struct sockaddr *) &sa, sizeof(sa)) < 0)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
                            "Error connecting to end server");
    }

    // The port is open and ready to go.
    // Build up the http GET command to send to the server.
    // To do:  We should really support http 1.1.  This implementation
    //         is weak.

    ostringstream outBuffer;

    outBuffer << "POST " << pathAsCharStar.get();

    if (queryAsCharStar.get() != 0)
    {
        // Tack on a ? before the fragment
        outBuffer << '?' << queryAsCharStar.get();
    }

    if (fragmentAsCharStar.get() != 0)
    {
        outBuffer << fragmentAsCharStar.get();
    }

    outBuffer << "HTTP/1.0\r\n"
        << "Content-Type: text/xml; charset=utf-8\r\n";

    outBuffer << "Host: " << hostNameAsCharStar.get();
    if (portNumber != 80)
    {
        outBuffer << ':' << portNumber;
    }
    outBuffer << "\r\n";

    outBuffer << "Content-Length: " << strlen(content) << "\r\n"
        << "SOAPAction: \"\"\r\n"
        << "\r\n";

    // Now the content
    outBuffer << content;

    // Send the http request
    string ostr = outBuffer.str();
    size_t lent = ostr.length();
    int  aLent = 0;
    if ((aLent = write(s, (void *) ostr.c_str(), lent)) != lent)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
                            "Error writing to socket");
    }

    char inBuffer[4000];
    char* inBufferEnd;
    char* inBufferPos;

    //
    // get the response, check the http header for errors from the server.
    //
    aLent = read(s, (void *)inBuffer, sizeof(inBuffer)-1);
    if (aLent <= 0)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
                            "Error reported reading socket");
    }

    inBufferEnd = inBuffer+aLent;
    *inBufferEnd = 0;

    // Find the break between the returned http header and any data.
    //  (Delimited by a blank line)
    // Hang on to any data for use by the first read from this BinHTTPURLInputStream.
    //
    bool headerRead = false;
    do {
        inBufferPos = strstr(inBuffer, "\r\n\r\n");
        if (inBufferPos != 0) {
            inBufferPos += 4;
            *(inBufferPos-2) = 0;
            headerRead = true;
        }
        else {
            inBufferPos = strstr(inBuffer, "\n\n");
            if (inBufferPos != 0) {
                inBufferPos += 2;
                *(inBufferPos-1) = 0;
                headerRead = true;
            }
            else {
                //
                // Header is not yet read, do another recv() to get more data...
                aLent = read(s,
                             inBufferEnd,
                             (sizeof(inBuffer) - 1) - (inBufferEnd - inBuffer));
                if (aLent <= 0) {
                    throw XSECException(XSECException::HTTPURIInputStreamError,
                                        "Error reported reading socket");
                }
                inBufferEnd = inBufferEnd + aLent;
                *inBufferEnd = 0;
            }
        }
    } while(headerRead == false);

    // Make sure the header includes an HTTP 200 OK response.
    //
    char *p = strstr(inBuffer, "HTTP");
    if (p == 0)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
                            "Error reported reading socket");
    }

    p = strchr(p, ' ');
    if (p == 0)
    {
        throw XSECException(XSECException::HTTPURIInputStreamError,
                            "Error reported reading socket");
    }

    int httpResponse = atoi(p);

    if (httpResponse == 302 || httpResponse == 301) {
        //Once grows, should use a switch
        char redirectBuf[256];
        int q;

        // Find the "Location:" string
        p = strstr(p, "Location:");
        if (p == 0)
        {
            throw XSECException(XSECException::HTTPURIInputStreamError,
                            "Error reported reading socket");
        }
        p = strchr(p, ' ');
        if (p == 0)
        {
            throw XSECException(XSECException::HTTPURIInputStreamError,
                            "Error reported reading socket");
        }

        // Now read
        p++;
        for (q=0; q < 255 && p[q] != '\r' && p[q] !='\n'; ++q)
            redirectBuf[q] = p[q];

        redirectBuf[q] = '\0';

        // Try to find this location
        XMLCh * recString = XMLString::transcode(redirectBuf);

        XSECSOAPRequestorSimple recurse(recString);
        XSEC_RELEASE_XMLCH(recString);
        return recurse.doRequest(request);

    }

    else if (httpResponse != 200)
    {
        // Most likely a 404 Not Found error.
        //   Should recognize and handle the forwarding responses.
        //
        char * q = strstr(p, "\n");
        if (q == NULL)
            q = strstr(p, "\r");
        if (q != NULL)
            *q = '\0';
        safeBuffer sb;
        sb.sbStrcpyIn("SOAPRequestorSimple HTTP Error : ");
        if (strlen(p) < 256)
            sb.sbStrcatIn(p);
        throw XSECException(XSECException::HTTPURIInputStreamError, sb.rawCharBuffer());

    }

    /* Now find out how long the return is */

    p = strstr(inBuffer, "Content-Length:");
    int responseLength;

    if (p == NULL) {
        // Need to work it out from the amount of data returned
        responseLength = -1;
    }
    else {

        p = strchr(p, ' ');
        p++;

        responseLength = atoi(p);
    }

    safeBuffer responseBuffer;
    lent = inBufferEnd - inBufferPos;
    responseBuffer.sbMemcpyIn(inBufferPos, lent);

    while (responseLength == -1 || lent < responseLength) {
        aLent = read(s, (void *)inBuffer, sizeof(inBuffer)-1);
        if (aLent > 0) {
            responseBuffer.sbMemcpyIn(lent, inBuffer, aLent);
            lent += aLent;
        }
        else {
            responseLength = 0;
        }
    }

    return parseAndUnwrap(responseBuffer.rawCharBuffer(), lent);
}

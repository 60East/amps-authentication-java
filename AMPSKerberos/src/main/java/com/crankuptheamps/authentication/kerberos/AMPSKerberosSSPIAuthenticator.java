//////////////////////////////////////////////////////////////////////////\
//
// Copyright (c) 2012-2019 60East Technologies Inc., All Rights Reserved.
//
// This computer software is owned by 60East Technologies Inc. and is
// protected by U.S. copyright laws and other laws and by international
// treaties.  This computer software is furnished by 60East Technologies
// Inc. pursuant to a written license agreement and may be used, copied,
// transmitted, and stored only in accordance with the terms of such
// license agreement and with the inclusion of the above copyright notice.
// This computer software or any other copies thereof may not be provided
// or otherwise made available to any other person.
//
// U.S. Government Restricted Rights.  This computer software: (a) was
// developed at private expense and is in all respects the proprietary
// information of 60East Technologies Inc.; (b) was not developed with
// government funds; (c) is a trade secret of 60East Technologies Inc.
// for all purposes of the Freedom of Information Act; and (d) is a
// commercial item and thus, pursuant to Section 12.212 of the Federal
// Acquisition Regulations (FAR) and DFAR Supplement Section 227.7202,
// Government's use, duplication or disclosure of the computer software
// is subject to the restrictions set forth by 60East Technologies Inc..
//
////////////////////////////////////////////////////////////////////////////

package com.crankuptheamps.authentication.kerberos;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.crankuptheamps.client.Authenticator;
import com.crankuptheamps.client.exception.AuthenticationException;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.SecBufferDesc;

import waffle.windows.auth.IWindowsSecurityContext;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

public class AMPSKerberosSSPIAuthenticator extends AMPSKerberosAuthenticatorBase implements Authenticator {

    private IWindowsSecurityContext _secContext;

    private static final Logger _logger = LoggerFactory.getLogger(AMPSKerberosSSPIAuthenticator.class);

    public AMPSKerberosSSPIAuthenticator(String spn_) throws AuthenticationException {
        super(spn_);
        AMPSKerberosUtils.validateSPNWithRealm(spn_);
    }

    @Override
    protected void init() throws AuthenticationException {
        _secContext = WindowsSecurityContextImpl.getCurrent("Negotiate", _spn);
        _principalName = _secContext.getPrincipalName();
    }

    @Override
    public String _authenticateImpl(String username_, String encodedInToken_) throws AuthenticationException {
        byte[] outToken = null;

        if (encodedInToken_ == null) {
            _logger.info("Initializing kerberos security context for user {} connecting to service {}", _principalName,
                    _spn);
            outToken = _secContext.getToken();
        } else {
            _logger.info("Finalizing kerberos authentication for user {} connecting to service {}", _principalName,
                    _spn);
            byte[] inToken = _base64.decode(encodedInToken_);
            SecBufferDesc inTokenSecBuffer = new SecBufferDesc(Sspi.SECBUFFER_TOKEN, inToken);
            _secContext.initialize(_secContext.getHandle(), inTokenSecBuffer, _spn);
        }

        return (outToken == null) ? "" : new String(_base64.encode(outToken));
    }

    @Override
    protected void dispose() throws AuthenticationException {
        if (_secContext != null) {
            _secContext.dispose();
            _secContext = null;
        }
    }
}

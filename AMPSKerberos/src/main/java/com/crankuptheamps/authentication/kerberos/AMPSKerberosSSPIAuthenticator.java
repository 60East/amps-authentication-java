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

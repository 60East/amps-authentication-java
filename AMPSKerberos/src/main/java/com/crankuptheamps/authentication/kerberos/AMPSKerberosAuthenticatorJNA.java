package com.crankuptheamps.authentication.kerberos;

import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.crankuptheamps.client.Authenticator;
import com.crankuptheamps.client.exception.AuthenticationException;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.SecBufferDesc;

import waffle.windows.auth.IWindowsSecurityContext;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

public class AMPSKerberosAuthenticatorJNA extends AMPSKerberosAuthenticatorBase implements Authenticator {

    private IWindowsSecurityContext _secContext;

    static Logger _logger = LoggerFactory.getLogger(AMPSKerberosAuthenticatorJNA.class);

    public AMPSKerberosAuthenticatorJNA(String spn_) throws AuthenticationException {
        super(spn_);
        AMPSKerberosUtils.validateSPNWithRealm(spn_);
        _secContext = WindowsSecurityContextImpl.getCurrent("Negotiate", spn_);
        _principalName = _secContext.getPrincipalName();
    }

    @Override
    public String authenticate(String username_, String encodedInToken_) throws AuthenticationException {
        byte[] outToken = null;

        if (encodedInToken_ == null) {
            _logger.info("Initializing kerberos security context for user {} connecting to service {}", _principalName,
                    _spn);
            outToken = _secContext.getToken();
        } else {
            _logger.info("Finalizing kerberos authentication for user {} connecting to service {}", _principalName,
                    _spn);
            byte[] inToken = Base64.getDecoder().decode(encodedInToken_);
            SecBufferDesc inTokenSecBuffer = new SecBufferDesc(Sspi.SECBUFFER_TOKEN, inToken);
            _secContext.initialize(_secContext.getHandle(), inTokenSecBuffer, _spn);
        }

        return (outToken == null) ? "" : new String(Base64.getEncoder().encode(outToken));
    }
}

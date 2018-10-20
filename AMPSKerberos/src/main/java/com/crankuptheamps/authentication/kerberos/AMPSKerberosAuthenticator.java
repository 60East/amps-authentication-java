package com.crankuptheamps.authentication.kerberos;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;
import java.util.Base64;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.ietf.jgss.Oid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.crankuptheamps.client.exception.AuthenticationException;
import com.sun.security.auth.callback.TextCallbackHandler;

public class AMPSKerberosAuthenticator extends AMPSKerberosAuthenticatorBase {
    private GSSContext _secContext;

    private static Logger _logger = LoggerFactory.getLogger(AMPSKerberosAuthenticator.class);

    public AMPSKerberosAuthenticator(String spn_, String loginContextName_) throws AuthenticationException {
        super(spn_);

        try {
            LoginContext loginContext = new LoginContext(loginContextName_, new TextCallbackHandler());
            loginContext.login();
            Subject subject = loginContext.getSubject();
            Principal principal = subject.getPrincipals().iterator().next();
            _principalName = principal.getName();

            Subject.doAs(subject, new java.security.PrivilegedExceptionAction<Object>() {
                public Object run() throws IOException, AuthenticationException {
                    try {
                        acquireCredentials();
                    } catch (AuthenticationException e) {
                        throw new AuthenticationException(e);
                    }
                    return null;
                }
            });
        } catch (LoginException | PrivilegedActionException e) {
            throw new AuthenticationException(e);
        }
    }

    private void acquireCredentials() throws AuthenticationException {
        try {
            GSSManager manager = GSSManager.getInstance();
            _logger.info("Acquiring kerberos credentials for user {} connecting to service {}", _principalName, _spn);
            GSSName clientName = manager.createName(_principalName, GSSName.NT_USER_NAME);
            GSSCredential clientCreds = manager.createCredential(clientName, 8 * 3600, (Oid[]) null,
                    GSSCredential.INITIATE_ONLY);

            GSSName peerName = manager.createName(_spn, GSSName.NT_HOSTBASED_SERVICE);
            _secContext = manager.createContext(peerName, null, clientCreds, GSSContext.DEFAULT_LIFETIME);
            _secContext.requestMutualAuth(true);
        } catch (GSSException e) {
            throw new AuthenticationException(e);
        }
    }

    private byte[] initializeSecurityContext(byte[] inToken_) throws AuthenticationException {
        try {
            return _secContext.initSecContext(inToken_, 0, inToken_.length);
        } catch (GSSException e) {
            throw new AuthenticationException(e);
        }
    }

    @Override
    public String authenticate(String username_, String encodedInToken_) throws AuthenticationException {
        byte[] inToken;
        if (encodedInToken_ == null) {
            _logger.info("Initializing kerberos security context for user {} connecting to service {}", _principalName,
                    _spn);
            inToken = new byte[0];
        } else {
            _logger.info("Finalizing kerberos authentication for user {} connecting to service {}", _principalName,
                    _spn);
            inToken = Base64.getDecoder().decode(encodedInToken_);
        }
        byte[] outToken = initializeSecurityContext(inToken);
        return (outToken == null) ? "" : new String(Base64.getEncoder().encode(outToken));
    }
}

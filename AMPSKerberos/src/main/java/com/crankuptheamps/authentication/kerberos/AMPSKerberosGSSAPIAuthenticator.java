package com.crankuptheamps.authentication.kerberos;

import java.io.IOException;
import java.security.Principal;
import java.security.PrivilegedActionException;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.xml.bind.DatatypeConverter;

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

public class AMPSKerberosGSSAPIAuthenticator extends AMPSKerberosAuthenticatorBase {
    private GSSContext _secContext;
    private int _lifetime;

    private static final Logger _logger = LoggerFactory.getLogger(AMPSKerberosGSSAPIAuthenticator.class);

    public AMPSKerberosGSSAPIAuthenticator(String spn_, String loginContextName_, int lifetime_)
            throws AuthenticationException {
        super(spn_);
        AMPSKerberosUtils.validateSPN(spn_);
        _spn = _spn.replaceAll("/", "@");
        _lifetime = lifetime_;

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

    public AMPSKerberosGSSAPIAuthenticator(String spn_, String loginContextName_) throws AuthenticationException {
        this(spn_, loginContextName_, 8 * 3600);
    }

    private void acquireCredentials() throws AuthenticationException {
        try {
            GSSManager manager = GSSManager.getInstance();
            _logger.info("Acquiring kerberos credentials for user {} connecting to service {}", _principalName, _spn);
            GSSName clientName = manager.createName(_principalName, GSSName.NT_USER_NAME);
            GSSCredential clientCreds = manager.createCredential(clientName, _lifetime, (Oid[]) null,
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
            inToken = DatatypeConverter.parseBase64Binary(encodedInToken_);
        }
        byte[] outToken = initializeSecurityContext(inToken);
        return (outToken == null) ? "" : DatatypeConverter.printBase64Binary(outToken);
    }

    @Override
    public void dispose() throws AuthenticationException {
        if (_secContext != null) {
            try {
                _secContext.dispose();
            } catch (GSSException e) {
                throw new AuthenticationException(e);
            }
        }
    }
}
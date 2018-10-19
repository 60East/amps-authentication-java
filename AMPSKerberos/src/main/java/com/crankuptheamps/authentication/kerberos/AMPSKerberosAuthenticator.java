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

import com.crankuptheamps.client.Authenticator;
import com.crankuptheamps.client.Message;
import com.crankuptheamps.client.exception.AuthenticationException;
import com.sun.security.auth.callback.TextCallbackHandler;

public class AMPSKerberosAuthenticator implements Authenticator {
    private String _spn;
    private GSSContext _secContext;
    private LoginContext _loginContext;

    public AMPSKerberosAuthenticator(String spn_, String loginContextName_) throws AuthenticationException {
        _spn = spn_;

        try {
            _loginContext = new LoginContext(loginContextName_, new TextCallbackHandler());
            _loginContext.login();

            Subject.doAs(_loginContext.getSubject(), new java.security.PrivilegedExceptionAction<Object>() {
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
            Subject s = _loginContext.getSubject();
            Principal p = s.getPrincipals().iterator().next();
            GSSName clientName = manager.createName(p.getName(), GSSName.NT_USER_NAME);
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
        byte[] inToken = (encodedInToken_ == null) ? new byte[0] : Base64.getDecoder().decode(encodedInToken_);
        byte[] outToken = initializeSecurityContext(inToken);
        return (outToken == null) ? "" : new String(Base64.getEncoder().encode(outToken));
    }

    @Override
    public String retry(String username_, String encodedInToken_) throws AuthenticationException {
        return authenticate(username_, encodedInToken_);
    }

    @Override
    public void completed(String username_, String encodedInToken_, int reason_) throws AuthenticationException {
        if (reason_ == Message.Reason.AuthDisabled) {
            return;
        }
        authenticate(username_, encodedInToken_);
    }
}

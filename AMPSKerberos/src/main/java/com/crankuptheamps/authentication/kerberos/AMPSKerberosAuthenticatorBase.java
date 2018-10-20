package com.crankuptheamps.authentication.kerberos;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.crankuptheamps.client.Authenticator;
import com.crankuptheamps.client.Message;
import com.crankuptheamps.client.exception.AuthenticationException;

public abstract class AMPSKerberosAuthenticatorBase implements Authenticator {

    protected String _spn;
    protected String _principalName;

    protected static Logger _logger = LoggerFactory.getLogger(AMPSKerberosAuthenticator.class);

    public AMPSKerberosAuthenticatorBase(String spn_) {
        super();
        _spn = spn_;
    }

    @Override
    public String retry(String username_, String encodedInToken_) throws AuthenticationException {
        return authenticate(username_, encodedInToken_);
    }

    @Override
    public void completed(String username_, String encodedInToken_, int reason_) throws AuthenticationException {
        if (reason_ == Message.Reason.AuthDisabled) {
            _logger.info("Authentication is disabled on the server side");
            return;
        }
        authenticate(username_, encodedInToken_);
    }

}
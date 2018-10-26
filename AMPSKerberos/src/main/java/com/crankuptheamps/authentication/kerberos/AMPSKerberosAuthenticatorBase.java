package com.crankuptheamps.authentication.kerberos;

import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.crankuptheamps.client.Authenticator;
import com.crankuptheamps.client.Message;
import com.crankuptheamps.client.exception.AuthenticationException;

public abstract class AMPSKerberosAuthenticatorBase implements Authenticator {

    protected String _spn;
    protected String _principalName;
    protected Base64 _base64;

    private static final Logger _logger = LoggerFactory.getLogger(AMPSKerberosGSSAPIAuthenticator.class);

    public AMPSKerberosAuthenticatorBase(String spn_) {
        super();
        _spn = spn_;
        _base64 = new Base64();
    }

    public abstract void dispose() throws AuthenticationException;

    @Override
    public String retry(String username_, String encodedInToken_) throws AuthenticationException {
        return authenticate(username_, encodedInToken_);
    }

    @Override
    public void completed(String username_, String encodedInToken_, int reason_) throws AuthenticationException {
        if (reason_ == Message.Reason.AuthDisabled) {
            _logger.info("Authentication is disabled on the server side");
            //TODO: Comment as to why we are disposing
            dispose();
            return;
        }
        authenticate(username_, encodedInToken_);
        //TODO: Comment as to why we are disposing
        dispose();
    }
}
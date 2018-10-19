package com.crankuptheamps.authentication.kerberos;

import com.crankuptheamps.client.Authenticator;
import com.crankuptheamps.client.Message;
import com.sun.jna.platform.win32.Sspi;
import com.sun.jna.platform.win32.Sspi.SecBufferDesc;

import waffle.windows.auth.IWindowsSecurityContext;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;
import waffle.windows.auth.impl.WindowsSecurityContextImpl;

import com.crankuptheamps.client.exception.AuthenticationException;

public class AMPSKerberosAuthenticatorJNA implements Authenticator {

    @Override
    public String authenticate(String username_, String encodedInToken_) throws AuthenticationException {
        // TODO Auto-generated method stub
        return null;
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

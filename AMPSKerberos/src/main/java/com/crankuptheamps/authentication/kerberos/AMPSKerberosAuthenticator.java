package com.crankuptheamps.authentication.kerberos;

import com.crankuptheamps.client.Authenticator;
import com.crankuptheamps.client.exception.AuthenticationException;

public class AMPSKerberosAuthenticator implements Authenticator {

	@Override
	public String authenticate(String username_, String currentPassword_) throws AuthenticationException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String retry(String username_, String password_) throws AuthenticationException {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void completed(String username_, String password_, int reason_) throws AuthenticationException {
		// TODO Auto-generated method stub

	}

}

package com.crankuptheamps.authentication.kerberos;

import org.junit.Assume;
import org.junit.Before;

import com.crankuptheamps.client.exception.AuthenticationException;

public class AMPSKerberosSSPIAuthenticatorTest extends AMPSKerberosAuthenticatorTestBase {
    @Before
    public void setUp() throws AuthenticationException {
        Assume.assumeTrue(System.getProperty("os.name").toLowerCase().startsWith("win"));
        super.setUp();
        _authenticator = new AMPSKerberosSSPIAuthenticator(_spn);
    }
}

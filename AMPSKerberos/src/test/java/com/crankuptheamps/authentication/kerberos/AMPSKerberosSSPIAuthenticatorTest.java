package com.crankuptheamps.authentication.kerberos;

import java.util.Properties;

import org.junit.Assume;
import org.junit.Before;

import com.crankuptheamps.client.exception.AuthenticationException;

public class AMPSKerberosSSPIAuthenticatorTest extends AMPSKerberosAuthenticatorTestBase {

    public AMPSKerberosSSPIAuthenticatorTest() throws AuthenticationException {
        super();
    }

    @Before
    public void setUp() throws AuthenticationException {
        super.setUp();
        Properties props = System.getProperties();
        // SSPI won't work when running on linux and also won't work, in our set up,
        // with a linux KDC.
        Assume.assumeTrue(props.getProperty("os.name").toLowerCase().startsWith("win"));
        Assume.assumeTrue(_authPlatform.equals("windows"));

        String ampsUser = "Administrator";
        _uri = "tcp://" + ampsUser + "@" + _ampsHost + ":" + _ampsPort + "/amps/json";
        _authenticator = new AMPSKerberosSSPIAuthenticator(_spn);
    }
}

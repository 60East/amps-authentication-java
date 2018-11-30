package com.crankuptheamps.authentication.kerberos;

import java.util.Properties;

import org.junit.Assume;
import org.junit.Before;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.crankuptheamps.client.exception.AuthenticationException;

/**
 * Unit test for AMPSKerberosAuthenticator.
 */
public class AMPSKerberosGSSAPIAuthenticatorTest extends AMPSKerberosAuthenticatorTestBase {
    private String _loginContextName;

    private static final Logger _logger = LoggerFactory.getLogger(AMPSKerberosGSSAPIAuthenticatorTest.class);

    public AMPSKerberosGSSAPIAuthenticatorTest() throws AuthenticationException {
        super();
    }

    @Before
    public void setUp() throws AuthenticationException {
        super.setUp();
        // Local authentication test exec via mvn
        // mvn -Djava.security.krb5.conf=/etc/krb5.conf
        // -Djava.security.auth.login.config=src/test/resources/jaas.conf
        // -Damps.auth.test.amps.host=ubuntu-desktop
        // -Damps.auth.test.amps.port=8554
        // -Damps.auth.test.login.ctx.name=TestClientLocalKDC
        // test

        Properties props = System.getProperties();

        if (props.getProperty("java.security.krb5.conf") == null) {
            throw new RuntimeException("java.security.krb5.conf must be set");
        }

        if (props.getProperty("java.security.auth.login.config") == null) {
            throw new RuntimeException("java.security.auth.login.config must be set");
        }

        _loginContextName = props.getProperty("amps.auth.test.login.ctx.name");
        if (_loginContextName == null) {
            _loginContextName = "LoginContext";
            _logger.info("No login context name set via amps.auth.test.login.ctx.name. Login context name set to \""
                    + _loginContextName + "\"");
        }

        _authenticator = new AMPSKerberosGSSAPIAuthenticator(_spn, _loginContextName);
    }
}

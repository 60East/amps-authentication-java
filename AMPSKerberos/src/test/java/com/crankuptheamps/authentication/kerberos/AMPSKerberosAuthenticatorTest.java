package com.crankuptheamps.authentication.kerberos;

import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.crankuptheamps.client.Client;
import com.crankuptheamps.client.exception.AMPSException;
import com.crankuptheamps.client.exception.AuthenticationException;

import junit.framework.Test;
import junit.framework.TestSuite;

/**
 * Unit test for AMPSKerberosAuthenticator.
 */
public class AMPSKerberosAuthenticatorTest extends AMPSKerberosAuthenticatorTestBase {
    private String _loginContextName;

    private static Logger _logger = LoggerFactory.getLogger(AMPSKerberosAuthenticatorTest.class);

    public AMPSKerberosAuthenticatorTest(String testName) {
        super(testName);

        // Local authentication test exec via mvn
        // mvn -Djava.security.krb5.conf=/etc/krb5.conf
        // -Djava.security.auth.login.config=src/test/resources/jaas.conf
        // -Damps.auth.test.amps.host=ubuntu-desktop
        // -Damps.auth.test.amps.port=8554
        // -Damps.auth.test.login.ctx.name=TestClientLocalKDC
        // test

        // mvn clean test -Dtest=your.package.TestClassName
        // mvn clean test -Dtest=your.package.TestClassName#particularMethod
        // to have errors got to console...
        // mvn clean test -Dtest=your.package.TestClassName -Dsurefire.useFile=false

        // String spn = "AMPS@ip-172-31-5-55.us-west-2.compute.internal";
        // String loginContextName = "TestClientWindowsKDC";

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
    }

    public static Test suite() {
        return new TestSuite(AMPSKerberosAuthenticatorTest.class);
    }

    public void testObtainToken() throws AuthenticationException {
        AMPSKerberosAuthenticator authenticator = new AMPSKerberosAuthenticator(_spn, _loginContextName);
        assertFalse(authenticator.authenticate(null, null).isEmpty());
    }

    public void testPublish() throws AMPSException {
        Client client = new Client("KerberosTestPublisher");
        try {
            client.connect(_uri);
            AMPSKerberosAuthenticator authenticator = new AMPSKerberosAuthenticator(_spn, _loginContextName);
            client.logon(10000, authenticator);
            client.publish("/topic", "{'foo': 'bar'}");
        } finally {
            client.close();
        }
        assertTrue(true); // An exception would have been thrown if authentication failed
    }
}

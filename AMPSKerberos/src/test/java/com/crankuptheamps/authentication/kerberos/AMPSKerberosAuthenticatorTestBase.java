package com.crankuptheamps.authentication.kerberos;

import static org.junit.Assert.*;

import java.util.Properties;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.crankuptheamps.client.Authenticator;
import com.crankuptheamps.client.Client;
import com.crankuptheamps.client.exception.AMPSException;
import com.crankuptheamps.client.exception.AuthenticationException;

public abstract class AMPSKerberosAuthenticatorTestBase {
    protected String _uri;
    protected String _spn;
    protected String _authPlatform;
    protected Authenticator _authenticator;

    private static final Logger _logger = LoggerFactory.getLogger(AMPSKerberosAuthenticatorTestBase.class);

    @Before
    public void setUp() throws AuthenticationException {
        Properties props = System.getProperties();

        String ampsHost = props.getProperty("amps.auth.test.amps.host");

        if (ampsHost == null) {
            _logger.warn("Kerberos tests will be skipped. Set amps.auth.test.amps.host in order to enable the tests.");
        }
        Assume.assumeTrue(ampsHost != null);

        String ampsPort = props.getProperty("amps.auth.test.amps.port");
        if (ampsPort == null) {
            throw new RuntimeException("amps.auth.test.amps.port must be set");
        }

        _authPlatform = props.getProperty("amps.auth.test.auth.platform");
        if (_authPlatform == null) {
            throw new RuntimeException("amps.auth.test.auth.platform must be set");
        }

        if ((!_authPlatform.equals("linux")) && (!_authPlatform.equals("windows"))) {
            throw new RuntimeException("amps.auth.test.auth.platform must be 'linux' or 'windows'");
        }

        _uri = "tcp://60east@" + ampsHost + ":" + ampsPort + "/amps/json";
        _spn = "AMPS/" + ampsHost;
    }

    @Test
    public void testObtainToken() throws AuthenticationException {
        String token = _authenticator.authenticate(null, null);
        assertFalse(token.isEmpty());
        assertTrue(token.startsWith("YII"));
    }

    @Test
    public void testPublish() throws AMPSException {
        Client client = new Client("KerberosTestPublisher");
        try {
            client.connect(_uri);
            client.logon(10000, _authenticator);
            client.publish("/topic", "{'foo': 'bar'}");

        } finally {
            client.close();
        }
        assertTrue(true); // An exception would have been thrown if authentication failed
    }
}

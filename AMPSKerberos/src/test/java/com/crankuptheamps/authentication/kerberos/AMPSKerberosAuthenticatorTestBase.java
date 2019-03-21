package com.crankuptheamps.authentication.kerberos;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
            _logger.warn("Kerberos tests are being skipped. Set the amps.auth.test.amps.host property to enable them.");
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

    @Test
    public void testMultipleAuth() throws AMPSException {
        Client client = new Client("KerberosTestPublisher");
        try {
            for (int i = 0; i < 10; ++i) {
                client.connect(_uri);
                client.logon(10000, _authenticator);
                client.close();
            }
        } finally {
            client.close();
        }
        assertTrue(true); // An exception would have been thrown if authentication failed
    }

    @Test
    public void testMultipleAuthWithFailure() throws AMPSException {
        Client client = new Client("KerberosTestPublisher");
        boolean errorThrown = false;
        try {
            for (int i = 0; i < 10; ++i) {
                if (i % 2 == 0) {
                    client.connect(_uri);
                    client.logon(10000, _authenticator);
                    client.close();
                } else {
                    try {
                        client.connect(_uri);
                        client.logon();
                    } catch (AuthenticationException e) {
                        errorThrown = true;
                    } finally {
                        client.close();
                    }
                }
            }
        } finally {
            client.close();
        }
        assertTrue(errorThrown); // An exception would have been thrown if authentication failed
    }
}

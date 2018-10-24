package com.crankuptheamps.authentication.kerberos;

import static org.junit.Assert.*;

import java.util.Properties;

import org.junit.Before;
import org.junit.Test;

import com.crankuptheamps.client.Authenticator;
import com.crankuptheamps.client.Client;
import com.crankuptheamps.client.exception.AMPSException;
import com.crankuptheamps.client.exception.AuthenticationException;

public abstract class AMPSKerberosAuthenticatorTestBase {
    protected String _uri;
    protected String _spn;
    protected Authenticator _authenticator;

    @Before
    public void setUp() throws AuthenticationException {
        Properties props = System.getProperties();

        String ampsHost = props.getProperty("amps.auth.test.amps.host");
        if (ampsHost == null) {
            throw new RuntimeException("amps.auth.test.amps.host must be set");
        }

        String ampsPort = props.getProperty("amps.auth.test.amps.port");
        if (ampsPort == null) {
            throw new RuntimeException("amps.auth.test.amps.port must be set");
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

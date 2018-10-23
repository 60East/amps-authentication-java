package com.crankuptheamps.authentication.kerberos;

import com.crankuptheamps.client.Client;
import com.crankuptheamps.client.exception.AMPSException;
import com.crankuptheamps.client.exception.AuthenticationException;

import junit.framework.Test;
import junit.framework.TestSuite;

public class AMPSKerberosAuthenticatorJNATest extends AMPSKerberosAuthenticatorTestBase {

    // TODO: Need to skip this test if not on windows
    public AMPSKerberosAuthenticatorJNATest(String testName_) {
        super(testName_);
    }

    public static Test suite() {
        return new TestSuite(AMPSKerberosAuthenticatorJNATest.class);
    }

    public void testObtainToken() throws AuthenticationException {
        AMPSKerberosAuthenticatorJNA authenticator = new AMPSKerberosAuthenticatorJNA(_spn);
        String token = authenticator.authenticate(null, null);
        assertFalse(token.isEmpty());
        assertTrue(token.startsWith("YII"));
    }

    public void testPublish() throws AMPSException {
        Client client = new Client("KerberosTestPublisher");
        try {
            client.connect(_uri);
            AMPSKerberosAuthenticatorJNA authenticator = new AMPSKerberosAuthenticatorJNA(_spn);
            client.logon(10000, authenticator);
            client.publish("messages", "{ \"message\" : \"Hello, world!\" } ");

        } finally {
            client.close();
        }
        assertTrue(true); // An exception would have been thrown if authentication failed
    }
}

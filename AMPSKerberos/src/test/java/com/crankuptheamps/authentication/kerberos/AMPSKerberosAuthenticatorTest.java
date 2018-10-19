package com.crankuptheamps.authentication.kerberos;

import java.util.Properties;

import com.crankuptheamps.client.Client;
import com.crankuptheamps.client.exception.AMPSException;
import com.crankuptheamps.client.exception.AuthenticationException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for AMPSKerberosAuthenticator.
 */
public class AMPSKerberosAuthenticatorTest extends TestCase {
    private String _uri;
    private String _spn;
    private String _loginContextName;

    /**
     * Create the test case
     *
     * @param testName name of the test case
     */
    public AMPSKerberosAuthenticatorTest(String testName) {
        super(testName);

        Properties props = System.getProperties();

        String krbConf = props.getProperty("amps.auth.test.krb5.conf");
        String jaasConf = props.getProperty("amps.auth.test.jaas.conf");
        String ampsHost = props.getProperty("amps.auth.test.amps.host");
        String ampsPort = props.getProperty("amps.auth.test.amps.port");
        _uri = "tcp://60east@" + ampsHost + ":" + ampsPort + "/amps/json";
        _spn = "AMPS@" + ampsHost;
        _loginContextName = props.getProperty("amps.auth.test.login.ctx.name");

        if (krbConf == null) {
            throw new RuntimeException("amps.auth.test.krb5.conf must be set");
        }

        if (jaasConf == null) {
            throw new RuntimeException("amps.auth.test.jaas.conf must be set");
        }

        if (ampsHost == null) {
            throw new RuntimeException("amps.auth.test.amps.host must be set");
        }

        if (ampsPort == null) {
            throw new RuntimeException("amps.auth.test.amps.port must be set");
        }

        if (_loginContextName == null) {
            throw new RuntimeException("amps.auth.test.login.ctx.name must be set");
        }

        // Local authentication test exec via mvn
        // mvn -Damps.auth.test.krb5.conf=/etc/krb5.conf
        // -Damps.auth.test.jaas.conf=src/test/resources/jaas.conf
        // -Damps.auth.test.amps.host=ubuntu-desktop -Damps.auth.test.amps.port=8554
        // -Damps.auth.test.login.ctx.name=TestClientLocalKDC test

        // mvn clean test -Dtest=your.package.TestClassName
        // mvn clean test -Dtest=your.package.TestClassName#particularMethod
        // to have errors got to console...
        // mvn clean test -Dtest=your.package.TestClassName -Dsurefire.useFile=false

        // String spn = "AMPS@ip-172-31-5-55.us-west-2.compute.internal";
        // String loginContextName = "TestClientWindowsKDC";

        // props.setProperty("sun.security.krb5.debug","true");
        props.setProperty("java.security.krb5.conf", krbConf);
        props.setProperty("java.security.auth.login.config", jaasConf);
    }

    /**
     * @return the suite of tests being tested
     */
    public static Test suite() {
        return new TestSuite(AMPSKerberosAuthenticatorTest.class);
    }

    /**
     * 
     * @throws AuthenticationException
     */
    public void testObtainToken() throws AuthenticationException {
        AMPSKerberosAuthenticator authenticator = new AMPSKerberosAuthenticator(_spn, _loginContextName);
        System.out.println(authenticator.authenticate(null, null));
    }

    public void testPublish() throws AMPSException {
        Client client = new Client("KerberosTestPublisher");
        try {
            client.connect(_uri);
            AMPSKerberosAuthenticator authenticator = new AMPSKerberosAuthenticator(_spn, _loginContextName);
            client.logon(10000, authenticator);
            client.publish("messages", "{ \"message\" : \"Hello, world!\" } ");

        } finally {
            client.close();
        }
    }
}

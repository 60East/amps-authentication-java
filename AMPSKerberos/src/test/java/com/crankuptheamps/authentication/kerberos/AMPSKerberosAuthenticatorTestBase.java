package com.crankuptheamps.authentication.kerberos;

import java.util.Properties;

import junit.framework.TestCase;

public abstract class AMPSKerberosAuthenticatorTestBase extends TestCase {
    protected String _uri;
    protected String _spn;

    public AMPSKerberosAuthenticatorTestBase(String testName) {
        super(testName);

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
        _spn = "AMPS@" + ampsHost;
    }

}

package com.crankuptheamps.authentication.kerberos;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;

import com.crankuptheamps.client.exception.AuthenticationException;

public class AMPSKerberosUtilsTest {

    List<String> _validSPNs;
    List<String> _validSPNsWithRealm;
    List<String> _invalidSPNs;

    @Before
    public void setUp() throws Exception {
        _validSPNs = new ArrayList<String>();
        _validSPNs.add("AMPS/localhost");
        _validSPNs.add("AMPS/localhost:1234");
        _validSPNs.add("AMPS/localhost.localdomain");
        _validSPNs.add("AMPS/localhost.localdomain:1234");
        _validSPNs.add("AMPS/ac-1234.localhost.com");
        _validSPNs.add("AMPS/ac-1234.localhost.com:1234");

        _validSPNsWithRealm = new ArrayList<String>();
        _validSPNsWithRealm.add("AMPS/localhost@SOMEREALM");
        _validSPNsWithRealm.add("AMPS/localhost@SOMEREALM.COM");
        _validSPNsWithRealm.add("AMPS/localhost@SOME.REALM.COM");
        _validSPNsWithRealm.add("AMPS/localhost:1234@SOMEREALM");
        _validSPNsWithRealm.add("AMPS/localhost:1234@SOMEREALM.COM");
        _validSPNsWithRealm.add("AMPS/localhost:1234@SOME.REALM.COM");
        _validSPNsWithRealm.add("AMPS/localhost.localdomain@SOMEREALM");
        _validSPNsWithRealm.add("AMPS/localhost.localdomain@SOMEREALM.COM");
        _validSPNsWithRealm.add("AMPS/localhost.localdomain@SOME.REALM.COM");
        _validSPNsWithRealm.add("AMPS/localhost.localdomain:1234@SOMEREALM");
        _validSPNsWithRealm.add("AMPS/localhost.localdomain:1234@SOMEREALM.COM");
        _validSPNsWithRealm.add("AMPS/localhost.localdomain:1234@SOME.REALM.COM");

        _invalidSPNs = new ArrayList<String>();
        _invalidSPNs.add("FOO");
        _invalidSPNs.add("localhost.localdomain");
        _invalidSPNs.add("AMPS@localhost");
        _invalidSPNs.add("AMPS@localhost.localdomain");
        _invalidSPNs.add("AMPS@localhost.localdomain");
        _invalidSPNs.add("AMPS@localhost.localdomain/FOO");
    }

    @Test
    public void testValidateSPN() throws AuthenticationException {
        for (String validSPN : _validSPNs) {
            AMPSKerberosUtils.validateSPN(validSPN);
        }
    }

    @Test
    public void testValidateSPNWithRealm1() throws AuthenticationException {
        for (String validSPN : _validSPNs) {
            AMPSKerberosUtils.validateSPN(validSPN);
        }
    }

    @Test
    public void testValidateSPNWithRealm2() throws AuthenticationException {
        for (String validSPN : _validSPNsWithRealm) {
            AMPSKerberosUtils.validateSPNWithRealm(validSPN);
        }
    }

    @Test
    public void testInvalidSPNs1() {
        for (String invalidSPN : _validSPNsWithRealm) {
            boolean exceptionRaised = false;
            try {
                AMPSKerberosUtils.validateSPN(invalidSPN);
            } catch (AuthenticationException e) {
                exceptionRaised = true;
            }
            assertTrue(exceptionRaised);
        }
    }

    @Test
    public void testInvalidSPNs2() {
        for (String invalidSPN : _invalidSPNs) {
            boolean exceptionRaised = false;
            try {
                AMPSKerberosUtils.validateSPN(invalidSPN);
            } catch (AuthenticationException e) {
                exceptionRaised = true;
            }
            assertTrue(exceptionRaised);
        }
    }

    @Test
    public void testInvalidSPNs3() {
        for (String invalidSPN : _invalidSPNs) {
            boolean exceptionRaised = false;
            try {
                AMPSKerberosUtils.validateSPNWithRealm(invalidSPN);
            } catch (AuthenticationException e) {
                exceptionRaised = true;
            }
            assertTrue(exceptionRaised);
        }
    }
}

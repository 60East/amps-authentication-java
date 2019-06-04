//////////////////////////////////////////////////////////////////////////\
//
// Copyright (c) 2012-2019 60East Technologies Inc., All Rights Reserved.
//
// This computer software is owned by 60East Technologies Inc. and is
// protected by U.S. copyright laws and other laws and by international
// treaties.  This computer software is furnished by 60East Technologies
// Inc. pursuant to a written license agreement and may be used, copied,
// transmitted, and stored only in accordance with the terms of such
// license agreement and with the inclusion of the above copyright notice.
// This computer software or any other copies thereof may not be provided
// or otherwise made available to any other person.
//
// U.S. Government Restricted Rights.  This computer software: (a) was
// developed at private expense and is in all respects the proprietary
// information of 60East Technologies Inc.; (b) was not developed with
// government funds; (c) is a trade secret of 60East Technologies Inc.
// for all purposes of the Freedom of Information Act; and (d) is a
// commercial item and thus, pursuant to Section 12.212 of the Federal
// Acquisition Regulations (FAR) and DFAR Supplement Section 227.7202,
// Government's use, duplication or disclosure of the computer software
// is subject to the restrictions set forth by 60East Technologies Inc..
//
////////////////////////////////////////////////////////////////////////////

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
    protected String _ampsHost;
    protected String _ampsPort;
    protected String _uri;
    protected String _spn;
    protected String _authPlatform;
    protected Authenticator _authenticator;

    private static final Logger _logger = LoggerFactory.getLogger(AMPSKerberosAuthenticatorTestBase.class);

    @Before
    public void setUp() throws AuthenticationException {
        Properties props = System.getProperties();

        _ampsHost = props.getProperty("amps.auth.test.amps.host");

        if (_ampsHost == null) {
            _logger.warn("Kerberos tests are being skipped. Set the amps.auth.test.amps.host property to enable them.");
        }
        Assume.assumeTrue(_ampsHost != null);

        _ampsPort = props.getProperty("amps.auth.test.amps.port");
        if (_ampsPort == null) {
            throw new RuntimeException("amps.auth.test.amps.port must be set");
        }

        _authPlatform = props.getProperty("amps.auth.test.auth.platform");
        if (_authPlatform == null) {
            throw new RuntimeException("amps.auth.test.auth.platform must be set");
        }

        if ((!_authPlatform.equals("linux")) && (!_authPlatform.equals("windows"))) {
            throw new RuntimeException("amps.auth.test.auth.platform must be 'linux' or 'windows'");
        }

        _spn = "AMPS/" + _ampsHost;
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

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

        String ampsUser = "60east";
        _uri = "tcp://" + ampsUser + "@" + _ampsHost + ":" + _ampsPort + "/amps/json";
        _authenticator = new AMPSKerberosGSSAPIAuthenticator(_spn, _loginContextName);
    }
}

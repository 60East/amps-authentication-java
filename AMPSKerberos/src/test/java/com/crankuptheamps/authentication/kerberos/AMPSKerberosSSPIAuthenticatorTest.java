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

import com.crankuptheamps.client.exception.AuthenticationException;

public class AMPSKerberosSSPIAuthenticatorTest extends AMPSKerberosAuthenticatorTestBase {

    public AMPSKerberosSSPIAuthenticatorTest() throws AuthenticationException {
        super();
    }

    @Before
    public void setUp() throws AuthenticationException {
        super.setUp();
        Properties props = System.getProperties();
        // SSPI won't work when running on linux and also won't work, in our set up,
        // with a linux KDC.
        Assume.assumeTrue(props.getProperty("os.name").toLowerCase().startsWith("win"));
        Assume.assumeTrue(_authPlatform.equals("windows"));

        String ampsUser = "Administrator";
        _uri = "tcp://" + ampsUser + "@" + _ampsHost + ":" + _ampsPort + "/amps/json";
        _authenticator = new AMPSKerberosSSPIAuthenticator(_spn);
    }
}

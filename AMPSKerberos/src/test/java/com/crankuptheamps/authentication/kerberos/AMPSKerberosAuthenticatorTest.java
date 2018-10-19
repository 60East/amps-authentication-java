package com.crankuptheamps.authentication.kerberos;

import java.util.Properties;

import com.crankuptheamps.client.exception.AuthenticationException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Unit test for AMPSKerberosAuthenticator.
 */
public class AMPSKerberosAuthenticatorTest extends TestCase {
	/**
	 * Create the test case
	 *
	 * @param testName name of the test case
	 */
	public AMPSKerberosAuthenticatorTest(String testName) {
		super(testName);

		Properties props = System.getProperties();
		// props.setProperty("sun.security.krb5.debug","true");
		props.setProperty("java.security.krb5.conf", "/home/ryan/projects/ryan/kerberos/krb5-ec2-windows.conf");
		props.setProperty("java.security.auth.login.config", "src/test/resources/jaas.conf");
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
		String spn = "AMPS@ip-172-31-5-55.us-west-2.compute.internal";
		String loginContextName = "TestClientWindowsKDC";
		AMPSKerberosAuthenticator authenticator = new AMPSKerberosAuthenticator(spn, loginContextName);
		System.out.println(authenticator.authenticate(null, null));
	}
}

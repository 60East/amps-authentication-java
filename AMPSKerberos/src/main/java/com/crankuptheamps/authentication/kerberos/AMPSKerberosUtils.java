package com.crankuptheamps.authentication.kerberos;

import com.crankuptheamps.client.exception.AuthenticationException;

public class AMPSKerberosUtils {

    private static String hostPattern = "(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\\-]*[a-zA-Z0-9])";
    private static String realmPattern = "@[\\w\\d]+([\\.\\w\\d]*)?";
    private static String spnPattern = "^(\\w+/)(" + hostPattern + ")(:\\d+)?";
    private static String spnFormat = "<service>/<host>[:<port>]";
    private static String spnPatternWithRealm = String.format("%s(%s)?", spnPattern, realmPattern);
    private static String spnFormatWithRealm = "<service>/<host>[:<port>][@REALM]";

    public static void validateSPN(String spn_) throws AuthenticationException {
        if (!spn_.matches(spnPattern)) {
            throw new AuthenticationException(
                    String.format("The specified SPN %s does not match the format %s", spn_, spnFormat));
        }
    }

    public static void validateSPNWithRealm(String spn_) throws AuthenticationException {
        if (!spn_.matches(spnPatternWithRealm)) {
            throw new AuthenticationException(
                    String.format("The specified SPN %s does not match the format %s", spn_, spnFormatWithRealm));
        }
    }
}

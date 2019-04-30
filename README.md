# AMPS Java Client Kerberos Authentication

## Dependencies

See `pom.xml`

## Example

For Kerberos authentication using Java there are two different `Authenticator` implmentations, one for GSSAPI based authentication and one for SSPI based authentication. GSSAPI is the only option for authentication when running on Linux, but it is supported on Windows as well. When using GSSAPI a JAAS configuration file is required. SSPI, on the other hand, uses Windows native system calls and thus is Windows only and does not require a JAAS configuration. In general, we recommend that `AMPSKerberosGSSAPIAuthenticator` is used when running on Linux and `AMPSKerberosSSPIAuthenticator` is used when running on Windows.

Below are two different JAAS configuration options. The first example will use Kerberos credentials in the user's Kerberos credentials cache or will prompt the user for a password to obtain the credentials. The second example utilizes a keytab to obtain the Kerberos credentials. When a JAAS configuration is utilized the `java.security.auth.login.config` property needs to be set to the path to the config file and the config file entry name needs to be passed to the `AMPSKerberosGSSAPIAuthenticator` along with the SPN.

```

TestClient {
    com.sun.security.auth.module.Krb5LoginModule required
    isInitiator=true
    principal="username"
    useTicketCache=true
    storeKey=true
};

TestClient {
    com.sun.security.auth.module.Krb5LoginModule required
    isInitiator=true
    useKeyTab=true
    keyTab="/path/to/username.keytab"
    principal="username@REALM"
    storeKey=true
    doNotPrompt=true
};

```

```java
import com.crankuptheamps.authentication.kerberos.AMPSKerberosGSSAPIAuthenticator;
import com.crankuptheamps.authentication.kerberos.AMPSKerberosSSPIAuthenticator;
import com.crankuptheamps.client.Authenticator;
import com.crankuptheamps.client.Client;
import com.crankuptheamps.client.exception.ConnectionException;

public class KerberosAuthExample 
{
    public static void main( String[] args ) throws ConnectionException
    {
        String username = "username";
        String hostname = "hostname";

        String amps_spn = "AMPS/" + hostname;
        String amps_uri = "tcp://" + username + "@" + hostname + ":10304/amps/json";

        // Authenticator authenticator = new AMPSKerberosGSSAPIAuthenticator(amps_spn, "TestClient");
        // Authenticator authenticator = new AMPSKerberosSSPIAuthenticator(amps_spn);

        Client client = new Client("KerberosExampleClient");
        try {
            client.connect(amps_uri);
            client.logon(5000, authenticator);

        } finally {
            client.close();
        }

    }
}

```

## See Also

[Kerberos Authentication Blog Article]()
[libamps_multi_authentication](http://devnull.crankuptheamps.com/documentation/html/5.3.0.0/user-guide/html/chapters/auxiliary_modules.html#authentication-with-the-amps-multimechanism-authentication-module) AMPS Server Module


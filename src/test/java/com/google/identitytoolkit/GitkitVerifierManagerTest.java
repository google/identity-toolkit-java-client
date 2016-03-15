package com.google.identitytoolkit;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import junit.framework.TestCase;

import net.oauth.jsontoken.crypto.Verifier;

import org.mockito.Mockito;

import java.util.List;

/**
 * Tests Gitkit verifier manager.
 */
public class GitkitVerifierManagerTest extends TestCase {

  public static final String CERT_0 = "-----BEGIN CERTIFICATE-----\n"
      + "MIIDDzCCAfegAwIBAgIJAMKLYPybcIAZMA0GCSqGSIb3DQEBBQUAMB4xHDAaBgNV\n"
      + "BAMME0dvb2dsZSBBdXRoIFRvb2xraXQwHhcNMTMwNDI1MTUyMDExWhcNMTQwNDI1\n"
      + "MTUyMDExWjAeMRwwGgYDVQQDDBNHb29nbGUgQXV0aCBUb29sa2l0MIIBIjANBgkq\n"
      + "hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyVZ3j4Uovsspa6dCiTZAC/SndulGDKYf\n"
      + "mVr95ea+u4k0XMvvd7w9k0wq4d1xagMIKHZhAnYLvYfW0O5D8+d58/+UJq4vrlY9\n"
      + "zOcTOsOoZ5tX325TMIJmn7IzMMpds1tA2MfWNiMkf/+AFZfxg14jyBeRdk4LVZWa\n"
      + "FxMz9Fs/23pTuNBYwGzM3xyZajgEhJ9gp3k95qlQPq00bIMa69YiAcmyr4RVYpgW\n"
      + "qd+WPdROEZvRLsCaIGTeehLR6zceUPrTofbOo82JI3/PTfJ+bm+IzXRq5Ogynfw6\n"
      + "f4z0pJ/YuUlmGD+rrm5Dfja/V3QTPyqzFpQSPXND7OdpT63MryKHtQIDAQABo1Aw\n"
      + "TjAdBgNVHQ4EFgQUwGCN266hsEwDjx2aNQ4cdPSjmJMwHwYDVR0jBBgwFoAUwGCN\n"
      + "266hsEwDjx2aNQ4cdPSjmJMwDAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQUFAAOC\n"
      + "AQEABDl3G5Ao3ZTXdeNoeF8knWl//6pyxz/Jhv1/PApA9NQpyhqijmGyDMvCLt0F\n"
      + "02HVTqg/MYG5zwUCroV9daraEdn5302sx8kh1Ei8SBCKzoDa7B8wSd2/KrEd6zsX\n"
      + "/7ZVzSNx37xk5Jhzz6EmXfY7z22DmFWggxyeTYGgR5YgKkuslbIxxEKjVhK5YK60\n"
      + "1pyRhl0tqe2xt+FMn0tvLdkCfVCvyDj2cD7g5XBVXZS4rqwfy1XpzQfSuU4sQcgn\n"
      + "VpgjVOtnax48yJFXeNTrOoTPiQV2AZQSrGuKoJ8GojM6oZuEv5S2moB3IMKyU5F3\n"
      + "RQ1NcLfJHhAz2ccdbaBXJaP4Hw==\n"
      + "-----END CERTIFICATE-----";
  public static final String CERT_1 = "-----BEGIN CERTIFICATE-----\n"
      + "MIIDHDCCAgSgAwIBAgIEnqP6TzANBgkqhkiG9w0BAQsFADAzMQ8wDQYDVQQDEwZH\n"
      + "aXRraXQxEzARBgNVBAoTCkdvb2dsZSBJbmMxCzAJBgNVBAYTAlVTMB4XDTE0MDQw\n"
      + "OTIwMjgyNVoXDTE1MDQwNDIwMjgyNVowMzEPMA0GA1UEAxMGR2l0a2l0MRMwEQYD\n"
      + "VQQKEwpHb29nbGUgSW5jMQswCQYDVQQGEwJVUzCCASIwDQYJKoZIhvcNAQEBBQAD\n"
      + "ggEPADCCAQoCggEBAJWD8U8ctUaeM2U4GodrjGptJcv67YoeahzPMSf8vSFDLodp\n"
      + "eg3TwQHl6sMul15EWJg9nByqa1rVqDi6zVlwGKTxLXoHTF5OrqB+SH/j97PTdNWa\n"
      + "qnuQTSJEBR3NDNAXu3gL+e9tDT6W6jpIdu9fvb0hLT0d7sNqM1jZnepqrQgMIWGP\n"
      + "Sna64rvuth/sfx7UCKYY9gXHG5u/fAOMyD9TcvUk5Xz83wWVMJJ0vkcHZGrr3ATo\n"
      + "QdhYXVWaKQ6x9CM4ckXx3lktOuvlf5dT7eo0oX1RUvr8mCzrd81oIfDe7AeI7CCG\n"
      + "gUEqOUsGvk3qnErcIVuPr4vxNLC0MKBvnFjWTLUCAwEAAaM4MDYwDAYDVR0TAQH/\n"
      + "BAIwADAWBgNVHSUBAf8EDDAKBggrBgEFBQcDAjAOBgNVHQ8BAf8EBAMCB4AwDQYJ\n"
      + "KoZIhvcNAQELBQADggEBAGhaFUl6sGvZ3eNmF+9L9qBH/R4BQ3UkdW8FOCynIjD5\n"
      + "yH5qXd/Zna0mY77tSTuCjn9oDzomTzzeQdABtSgO3vQrf3YwpEzbBKTHyX2bWojT\n"
      + "vnZrFYkZ8GdfN+jyrGekFNFmQoeJrUGTyVjUMxj6UmcsgIpJWO6kMQv9DDtk0XL2\n"
      + "4GOhxk3MEm044qAT+D2OUlPCwzQhoG2idNH7ffnc1cYOsclpjJvdxiXJkzqSTpro\n"
      + "cmBuBSaCW3N0YgzTOEj+pC0rZKHuawyn4QYvvisLrCsTx81UiBW5GsK8MpmMsvPh\n"
      + "l/KAz8x0PKbbLtjNKW93nqdC4cumST7Q579Xs8USZrU=\n"
      + "-----END CERTIFICATE-----\n";
  public static final String TEST_CERTS = "{\n"
      + " \"0\": \"" + CERT_0 + "\",\n"
      + " \"1\": \"" + CERT_1 + "\"}";

  private RpcHelper mockRpc = Mockito.mock(RpcHelper.class);
  private GitkitVerifierManager verifierManager;

  @Override
  public void setUp() {
    verifierManager = new GitkitVerifierManager(mockRpc);
  }

  public void testFindVerifiers() throws Exception {
    when(mockRpc.downloadCerts()).thenReturn(TEST_CERTS);
    List<Verifier> verifiers = verifierManager.findVerifier("any-issuer", "0");
    assertEquals(1, verifiers.size());
    verifiers = verifierManager.findVerifier("any-issuer", "1");
    assertEquals(1, verifiers.size());
    // should send one request only
    verify(mockRpc).downloadCerts();
  }
}

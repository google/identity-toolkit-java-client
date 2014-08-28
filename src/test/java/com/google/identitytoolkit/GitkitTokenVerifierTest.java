package com.google.identitytoolkit;

import com.google.common.io.BaseEncoding;

import junit.framework.TestCase;

/**
 * Tests {@code GitkitTokenVerifier}.
 */
public class GitkitTokenVerifierTest extends TestCase {

  private static final String SIG_BASE_STRING =
      "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwczovL2dpdGtpdC5nb29nbGUuY29tLyIsImF1ZCI6Ijk"
      + "yNDIyNjUwNDE4My5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbSIsImlhdCI6MTM5NTI3MDMzNCwiZXh"
      + "wIjoxMzk2NDc5OTM0LCJ1c2VyX2lkIjoiMTIzNCIsImVtYWlsIjoiMTIzNEBleGFtcGxlLmNvbSIsInZ"
      + "lcmlmaWVkIjpmYWxzZX0";

  private static final String SIG_STRING =
      "a4hkZpl37nzHTX31-7z624ZnWXvWwScPhfyTVsW4kWN9DuAlaiya3R0p3B5"
          + "g_dw86DRoMMP9QvdsMfp9AOJ-4ciInhfh6sRWOl7jVwSC3zvcUjyLevBcnSvMQgb67Ll9ceF5oGLYZ_N"
          + "tHt3kqsxyV0LlgUxzaD45jNHXBpFgnM8XZLBNeVtEAeXkpL89RIJ5PCyXdHaA3DBADKO6VveEVrLoPdq"
          + "B9ss4behW6Nc4Zl8u5bA4ueJ_Y4-R_ydUyNtcuFXvZQgI1sRrd9b1Ath5e2OGY3r-2wuu3Yy0hbaU2Fp"
          + "0cuf1M7audo5i-8LVK7Mvm2DtPvnNUBJP0znvG3Z7lg";

  public void testRsa256Verifier() throws Exception {
    GitkitTokenVerifier verifier = new GitkitTokenVerifier(GitkitVerifierManagerTest.CERT_0);
    byte[] signature = BaseEncoding.base64Url().decode(SIG_STRING);
    verifier.verifySignature(SIG_BASE_STRING.getBytes(), signature);
  }
}

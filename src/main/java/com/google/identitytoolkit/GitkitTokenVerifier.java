/*
 * Copyright 2014 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.identitytoolkit;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.io.BaseEncoding;

import net.oauth.jsontoken.crypto.RsaSHA256Verifier;
import net.oauth.jsontoken.crypto.Verifier;

import java.io.ByteArrayInputStream;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * JWT signature verifier.
 */
public class GitkitTokenVerifier implements Verifier {

  @VisibleForTesting
  final RsaSHA256Verifier verifier;

  public GitkitTokenVerifier(String cert) {
    String pem = cert.replaceAll("-----BEGIN CERTIFICATE-----", "")
        .replaceAll("-----END CERTIFICATE-----", "")
        .replaceAll("\n", "");
    byte[] der = BaseEncoding.base64().decode(pem);
    CertificateFactory factory;
    try {
      factory = CertificateFactory.getInstance("X509");
    } catch (CertificateException e) {
      throw new RuntimeException("No X509 instance.", e);
    }
    X509Certificate x509Cert;
    try {
      x509Cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
    } catch (CertificateException e) {
      throw new RuntimeException("Certificate exception.", e);
    }
    verifier = new RsaSHA256Verifier(x509Cert.getPublicKey());
  }

  @Override
  public void verifySignature(byte[] source, byte[] signature) throws SignatureException {
    verifier.verifySignature(source, signature);
  }
}

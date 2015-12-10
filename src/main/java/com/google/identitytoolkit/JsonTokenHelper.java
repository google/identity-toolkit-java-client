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

import com.google.common.base.Joiner;
import com.google.common.base.Optional;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.gson.JsonObject;

import net.oauth.jsontoken.Checker;
import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.JsonTokenParser;
import net.oauth.jsontoken.crypto.SignatureAlgorithm;
import net.oauth.jsontoken.discovery.VerifierProviders;

import java.security.SignatureException;
import java.util.Arrays;
import java.util.List;

/**
 * Helps to find a JWT verifier.
 */
public class JsonTokenHelper {
  public static final String ID_TOKEN_EMAIL = "email";
  public static final String ID_TOKEN_USER_ID = "user_id";
  public static final String ID_TOKEN_PROVIDER = "provider_id";
  public static final String ID_TOKEN_DISPLAY_NAME = "display_name";
  public static final String ID_TOKEN_PHOTO_URL = "photo_url";
  private final JsonTokenParser parser;

  public JsonTokenHelper(RpcHelper rpcHelper, String serverApiKey, String... audiences) {
    VerifierProviders verifierProviders = new VerifierProviders();
    verifierProviders.setVerifierProvider(SignatureAlgorithm.RS256,
        new GitkitVerifierManager(rpcHelper, serverApiKey));
    parser = new JsonTokenParser(verifierProviders, new AudienceChecker(audiences));
  }

  public JsonToken verifyAndDeserialize(String token) throws SignatureException {
    return parser.verifyAndDeserialize(token);
  }

  /**
   * Checks the token is indeed for this RP.
   */
  public static class AudienceChecker implements Checker {

    private final List<String> expectedAudiences;

    public AudienceChecker(String... audiences) {
      expectedAudiences = Arrays.asList(audiences);
    }

    @Override
    public void check(JsonObject payload) throws SignatureException {
      if (!payload.has(JsonToken.AUDIENCE)) {
        throw new SignatureException("No audience in payload.");
      }
      final String audienceInIdToken = payload.get(JsonToken.AUDIENCE).getAsString();
      Optional<String> matchedAud = Iterables.tryFind(
          expectedAudiences,
          new Predicate<String>() {
            public boolean apply(String aud) {
              return audienceInIdToken.equals(aud);
            }
          });

      if (!matchedAud.isPresent()) {
        throw new SignatureException(String.format(
            "Gitkit token audience(%s) doesn't match projectId or clientId in server configuration",
            audienceInIdToken));
      }
    }
  }
}

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
import com.google.common.collect.Maps;
import com.google.common.io.BaseEncoding;

import net.oauth.jsontoken.JsonToken;
import net.oauth.jsontoken.crypto.RsaSHA256Signer;

import org.joda.time.Instant;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Wraps the http interactions for Gitkit APIs.
 */
public class RpcHelper {

  @VisibleForTesting
  static final String GITKIT_SCOPE = "https://www.googleapis.com/auth/identitytoolkit";
  @VisibleForTesting
  static final String TOKEN_SERVER = "https://accounts.google.com/o/oauth2/token";

  private static final Logger log = Logger.getLogger(RpcHelper.class.getName());
  private final RsaSHA256Signer signer;
  private final String gitkitApiUrl;
  private final HttpSender httpSender;

  public RpcHelper(HttpSender httpSender, String gitkitApiUrl, String serviceAccountEmail,
      InputStream keyStream) {
    this.gitkitApiUrl = gitkitApiUrl;
    this.httpSender = httpSender;
    signer = initRsaSHA256Signer(serviceAccountEmail, keyStream);
  }

  public JSONObject createAuthUri(String identifier, String continueUri, String context)
      throws GitkitServerException, GitkitClientException {
    JSONObject params = new JSONObject();
    try {
      if (identifier != null) {
        params.put("identifier", identifier);
      }
      if (continueUri != null) {
        params.put("continueUri", continueUri);
      }
      if (context != null) {
        params.put("context", context);
      }
      return invokeGitkitApi("createAuthUri", params, null);
    } catch (JSONException e) {
      throw new GitkitServerException(e);
    }
  }

  public JSONObject verifyAssertion(String requestUri, String postBody)
      throws GitkitServerException, GitkitClientException {
    JSONObject params = new JSONObject();
    try {
      params.put("requestUri", requestUri);
      if (postBody != null) {
        params.put("postBody", postBody);
      }
      return invokeGitkitApi("verifyAssertion", params, null);
    } catch (JSONException e) {
      throw new GitkitServerException(e);
    }
  }

  public JSONObject getOobCode(JSONObject resetReq)
      throws GitkitClientException, GitkitServerException {
    return invokeGoogle2LegOauthApi("getOobConfirmationCode", resetReq);
  }

  /**
   * Uses idToken to retrieve the user account information from GITkit service.
   *
   * @param idToken
   */
  public JSONObject getAccountInfo(String idToken)
      throws GitkitClientException, GitkitServerException {
    try {
      // Uses idToken to make the server call to GITKit
      JSONObject params = new JSONObject().put("idToken", idToken);
      return invokeGoogle2LegOauthApi("getAccountInfo", params);
    } catch (JSONException e) {
      throw new GitkitServerException("OAuth API failed");
    }
  }

  /**
   * Using 2-Leg Oauth (i.e. Service Account).
   */
  public JSONObject getAccountInfoById(String localId)
      throws GitkitClientException, GitkitServerException {
    try {
      JSONObject params = new JSONObject()
          .put("localId", new JSONArray().put(localId));
      return invokeGoogle2LegOauthApi("getAccountInfo", params);
    } catch (JSONException e) {
      throw new GitkitServerException(e);
    }
  }

  /**
   * Using 2-Leg Oauth (i.e. Service Account).
   */
  public JSONObject getAccountInfoByEmail(String email)
      throws GitkitClientException, GitkitServerException {
    try {
      JSONObject params = new JSONObject()
          .put("email", new JSONArray().put(email));
      return invokeGoogle2LegOauthApi("getAccountInfo", params);
    } catch (JSONException e) {
      throw new GitkitServerException(e);
    }
  }

  public JSONObject updateAccount(GitkitUser account)
      throws GitkitServerException, GitkitClientException {
    try {
      JSONObject params = new JSONObject()
          .put("email", account.getEmail())
          .put("localId", account.getLocalId());
      if (account.getName() != null) {
        params.put("displayName", account.getName());
      }
      if (account.getHash() != null) {
        params.put("password", account.getHash());
      }
      return invokeGoogle2LegOauthApi("setAccountInfo", params);
    } catch (JSONException e) {
      throw new GitkitServerException(e);
    }
  }

  public JSONObject downloadAccount(String nextPageToken, Integer maxResults)
      throws GitkitClientException, GitkitServerException {
    try {
      JSONObject params = new JSONObject();
      if (nextPageToken != null) {
        params.put("nextPageToken", nextPageToken);
      }
      if (maxResults != null) {
        params.put("maxResults", maxResults);
      }
      return invokeGoogle2LegOauthApi("downloadAccount", params);
    } catch (JSONException e) {
      throw new GitkitServerException(e);
    }
  }

  public JSONObject uploadAccount(String hashAlgorithm, byte[] hashKey, List<GitkitUser> accounts,
                                  byte[] saltSeparator, Integer rounds, Integer memoryCost)
          throws GitkitClientException, GitkitServerException {
    try {
      JSONObject params = new JSONObject()
          .put("hashAlgorithm", hashAlgorithm)
          .put("signerKey", BaseEncoding.base64Url().encode(hashKey))
          .put("users", toJsonArray(accounts));
        if (saltSeparator != null) {
            params.put("saltSeparator", BaseEncoding.base64Url().encode(saltSeparator));
        }
        if (rounds != null) {
            params.put("rounds", rounds);
        }
        if (memoryCost != null) {
            params.put("memoryCost", memoryCost);
        }
      return invokeGoogle2LegOauthApi("uploadAccount", params);
    } catch (JSONException e) {
      throw new GitkitServerException(e);
    }
  }

  public JSONObject deleteAccount(String localId)
      throws GitkitClientException, GitkitServerException {
    try {
      JSONObject params = new JSONObject().put("localId", localId);
      return invokeGoogle2LegOauthApi("deleteAccount", params);
    } catch (JSONException e) {
      throw new GitkitServerException(e);
    }
  }

  String downloadCerts(String serverApiKey) throws IOException {
    String certUrl = gitkitApiUrl + "publicKeys";
    Map<String, String> headers = Maps.newHashMap();
    if (serverApiKey != null) {
      certUrl += "?key=" + serverApiKey;
    } else {
      try {
        headers.put("Authorization", "Bearer " + getAccessToken());
      } catch (GeneralSecurityException e) {
        throw new IOException(e);
      } catch (JSONException e) {
        throw new IOException(e);
      }
    }
    return httpSender.get(certUrl, headers);
  }

  @VisibleForTesting
  JSONObject invokeGoogle2LegOauthApi(String method, JSONObject req)
      throws GitkitClientException, GitkitServerException {
    try {
      String accessToken = getAccessToken();
      return invokeGitkitApi(method, req, accessToken);
    } catch (GeneralSecurityException e) {
      throw new GitkitServerException(e);
    } catch (JSONException e) {
      throw new GitkitServerException(e);
    } catch (IOException e) {
      throw new GitkitServerException(e);
    }
  }

  @VisibleForTesting
  String getAccessToken() throws GeneralSecurityException, IOException, JSONException {
    String assertion = signServiceAccountRequest();
    String data = "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion="
        + assertion;
    Map<String, String> headers = Maps.newHashMap();
    headers.put("Content-Type", "application/x-www-form-urlencoded");
    String response = httpSender.post(TOKEN_SERVER, data, headers);
    return new JSONObject(response).getString("access_token");
  }

  @VisibleForTesting
  String signServiceAccountRequest() throws GeneralSecurityException {
    JsonToken assertion = new JsonToken(signer);
    assertion.setAudience(TOKEN_SERVER);
    assertion.setParam("nonce", "nonce");
    assertion.setParam("scope", GITKIT_SCOPE);
    assertion.setIssuedAt(new Instant());
    assertion.setExpiration(new Instant().plus(60 * 60 * 1000));
    return assertion.serializeAndSign();
  }

  private JSONObject invokeGitkitApi(String method, JSONObject params, String accessToken)
      throws GitkitClientException, GitkitServerException {
    try {
      Map<String, String> headers = Maps.newHashMap();
      if (accessToken != null) {
        headers.put("Authorization", "Bearer " + accessToken);
      }
      headers.put("Content-Type", "application/json");
      String response = httpSender.post(gitkitApiUrl + method, params.toString(), headers);
      return checkGitkitException(response);
    } catch (IOException e) {
      throw new GitkitServerException(e);
    }
  }

  private RsaSHA256Signer initRsaSHA256Signer(String serviceAccountEmail, InputStream keyStream) {
    try {
      if (serviceAccountEmail != null && keyStream != null) {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(keyStream, "notasecret".toCharArray());
        return new RsaSHA256Signer(
            serviceAccountEmail,
            null,
            (RSAPrivateKey) keyStore.getKey("privatekey", "notasecret".toCharArray()));
      }
    } catch (KeyStoreException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    } catch (CertificateException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    } catch (UnrecoverableKeyException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    } catch (NoSuchAlgorithmException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    } catch (IOException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    } catch (InvalidKeyException e) {
      log.log(Level.WARNING, "can not initialize service account signer: " + e.getMessage(), e);
    }
    log.warning("service account is set to null due to: email = " + serviceAccountEmail
        + "keystream = " + keyStream);
    return null;
  }

  private static JSONArray toJsonArray(List<GitkitUser> accounts) throws JSONException {
    JSONArray infos = new JSONArray();
    for (GitkitUser account : accounts) {
      JSONObject user = new JSONObject();
      user.put("email", account.getEmail());
      user.put("localId", account.getLocalId());
      if (account.getHash() != null) {
        user.put("passwordHash", BaseEncoding.base64Url().encode(account.getHash()));
      }
      if (account.getSalt() != null) {
        user.put("salt", BaseEncoding.base64Url().encode(account.getSalt()));
      }
      if (account.getProviders() != null) {
        JSONArray providers = new JSONArray();
        for (GitkitUser.ProviderInfo idpInfo : account.getProviders()) {
          providers.put(new JSONObject()
              .put("federatedId", idpInfo.getFederatedId())
              .put("providerId", idpInfo.getProviderId()));
        }
        user.put("providerUserInfo", providers);
      }
      infos.put(user);
    }
    return infos;
  }

  @VisibleForTesting
  JSONObject checkGitkitException(String response)
      throws GitkitClientException, GitkitServerException {
    try {
      JSONObject result = new JSONObject(response);
      if (!result.has("error")) {
        return result;
      }
      // Error handling
      JSONObject error = result.getJSONObject("error");
      String code = error.optString("code");
      if (code != null) {
        if (code.startsWith("4")) {
          // 4xx means client input error
          throw new GitkitClientException(error.optString("message"));
        } else {
          throw new GitkitServerException(error.optString("message"));
        }
      }
    } catch (JSONException e) {
      log.log(Level.WARNING, "Server response exception: " + e.getMessage(), e);
    }
    throw new GitkitServerException("null error code from Gitkit server");
  }
}

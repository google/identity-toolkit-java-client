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

import static org.mockito.Matchers.anyMapOf;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.io.BaseEncoding;

import junit.framework.TestCase;

import org.json.JSONArray;
import org.json.JSONObject;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.util.Iterator;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * Test GitkitClient.
 */
public class GitkitClientTest extends TestCase {

  private final HttpSender mockSender = Mockito.mock(HttpSender.class);
  private Map<String, String> headers;
  private GitkitClient gitkitClient;

  @Override
  protected void setUp() throws Exception {
    when(mockSender
        .post(eq(RpcHelper.TOKEN_SERVER), anyString(), anyMapOf(String.class, String.class)))
            .thenReturn("{'access_token': 'fake-token'}");
    headers = Maps.newHashMap();
    headers.put("Authorization", "Bearer fake-token");
    headers.put("Content-Type", "application/json");
    gitkitClient = new GitkitClient.Builder()
        .setKeyStream(new ByteArrayInputStream(TestConfig.getP12Key()))
        .setServiceAccountEmail("dev@developer.gserviceaccount.com")
        .setGoogleClientId("test-client-id.apps.googleusercontent.com")
        .setHttpSender(mockSender)
        .setWidgetUrl("http://example.com:80/gitkit")
        .build();
  }

  public void testGetAccountInfo() throws Exception {
    String expectedApiUrl = GitkitClient.GITKIT_API_BASE + "getAccountInfo";
    when(mockSender.post(eq(expectedApiUrl), anyString(), eq(headers)))
        .thenReturn("{'users': [{'email': 'user@example.com', 'localId': '1234'}]}");

    GitkitUser user = gitkitClient.getUserByEmail("user@example.com");
    assertEquals("1234", user.getLocalId());
  }

  public void testGetAllUsers() throws Exception {
    JSONObject user1 = new JSONObject().put("email", "1111@example.com").put("localId", "1111");
    JSONObject user2 = new JSONObject().put("email", "2222@example.com").put("localId", "2222");
    String downloadResponse = new JSONObject()
        .put("nextPageToken", "100")
        .put("users", new JSONArray().put(user1).put(user2))
        .toString();
    String expectedApiUrl = GitkitClient.GITKIT_API_BASE + "downloadAccount";
    // first download request
    when(mockSender.post(expectedApiUrl, "{}", headers))
        .thenReturn(downloadResponse);
    // second download request should contain the next page token
    when(mockSender.post(expectedApiUrl, "{\"nextPageToken\":\"100\"}", headers))
        .thenReturn("{}");

    Iterator<GitkitUser> iterator = gitkitClient.getAllUsers();
    // iterator should contain user1 and user2
    GitkitUser user = iterator.next();
    assertEquals(user1.getString("localId"), user.getLocalId());
    assertEquals(user1.getString("email"), user.getEmail());
    user = iterator.next();
    assertEquals(user2.getString("localId"), user.getLocalId());
    assertEquals(user2.getString("email"), user.getEmail());
    // should have no more data
    assertFalse(iterator.hasNext());
  }

  public void testDeleteAccount() throws Exception {
    String userId = "1111";
    String expectedApiUrl = GitkitClient.GITKIT_API_BASE + "deleteAccount";
    when(mockSender.post(expectedApiUrl, "{\"localId\":\"" + userId + "\"}", headers))
        .thenReturn("{}");

    gitkitClient.deleteUser(userId);
  }

  public void testUploadAccount() throws Exception {
    String hashKey = "hash-key";
    String hashAlgorithm = "sha256";
    GitkitUser user1 = new GitkitUser()
        .setLocalId("1111")
        .setEmail("1111@example.com")
        .setHash("random-hash".getBytes());
    String expectedApiUrl = GitkitClient.GITKIT_API_BASE + "uploadAccount";
    when(mockSender.post(eq(expectedApiUrl), anyString(), eq(headers))).thenReturn("{}");

    gitkitClient.uploadUsers(hashAlgorithm, hashKey.getBytes(), Lists.newArrayList(user1));

    // check the upload request
    ArgumentCaptor<String> captor = ArgumentCaptor.forClass(String.class);
    verify(mockSender).post(eq(expectedApiUrl), captor.capture(), eq(headers));
    JSONObject postData = new JSONObject(captor.getValue());
    assertEquals(hashAlgorithm, postData.getString("hashAlgorithm"));
    assertEquals(BaseEncoding.base64().encode(hashKey.getBytes()), postData.getString("signerKey"));
    // check the user data in the request
    JSONArray userData = postData.getJSONArray("users");
    assertEquals(1, userData.length());
    assertEquals(user1.getEmail(), userData.getJSONObject(0).getString("email"));
    assertEquals(user1.getLocalId(), userData.getJSONObject(0).getString("localId"));
    assertEquals(
        BaseEncoding.base64().encode(user1.getHash()),
        userData.getJSONObject(0).getString("passwordHash"));
  }

  public void testUpdateUser() throws Exception {
    GitkitUser user = new GitkitUser()
        .setLocalId("1111")
        .setName("New Name");
    String expectedApiUrl = GitkitClient.GITKIT_API_BASE + "setAccountInfo";
    ArgumentCaptor<String> postCaptor = ArgumentCaptor.forClass(String.class);
    when(mockSender.post(eq(expectedApiUrl), postCaptor.capture(), eq(headers)))
        .thenReturn("{'localId':'1111','displayName':'New Name','email':'1111@example.com'}");

    gitkitClient.updateUser(user);
    JSONObject requestBody = new JSONObject(postCaptor.getValue());
    assertEquals(user.getLocalId(), requestBody.getString("localId"));
    assertEquals(user.getName(), requestBody.getString("displayName"));
  }

  public void testGetOobCode() throws Exception {
    Cookie[] gitkitCookie = {new Cookie("gtoken", "fake-token")};
    HttpServletRequest mockRequest = Mockito.mock(HttpServletRequest.class);
    when(mockRequest.getCookies()).thenReturn(gitkitCookie);
    when(mockRequest.getParameter("action")).thenReturn("resetPassword");
    when(mockRequest.getParameter("email")).thenReturn("1111@example.com");
    when(mockRequest.getParameter("challenge")).thenReturn("what is the number");
    when(mockRequest.getParameter("response")).thenReturn("8888");
    when(mockRequest.getRemoteUser()).thenReturn("1.1.1.1");
    String expectedApiUrl = GitkitClient.GITKIT_API_BASE + "getOobConfirmationCode";
    when(mockSender.post(eq(expectedApiUrl), anyString(), eq(headers)))
        .thenReturn("{'oobCode':'fake-oob-code'}");

    GitkitClient.OobResponse oobResponse = gitkitClient.getOobResponse(mockRequest);

    assertEquals(GitkitClient.OobAction.RESET_PASSWORD, oobResponse.getOobAction());
    assertEquals(
        "http://example.com:80/gitkit?mode=resetPassword&oobCode=fake-oob-code",
        oobResponse.getOobUrl().get());
  }

  public void testGetOobCode_OobCodeMissing() throws Exception {
    Cookie[] gitkitCookie = {new Cookie("gtoken", "fake-token")};
    HttpServletRequest mockRequest = Mockito.mock(HttpServletRequest.class);
    when(mockRequest.getCookies()).thenReturn(gitkitCookie);
    when(mockRequest.getParameter("action")).thenReturn("resetPassword");
    when(mockRequest.getParameter("email")).thenReturn("1111@example.com");
    when(mockRequest.getParameter("challenge")).thenReturn("what is the number");
    when(mockRequest.getParameter("response")).thenReturn("8888");
    when(mockRequest.getRemoteUser()).thenReturn("1.1.1.1");
    String expectedApiUrl = GitkitClient.GITKIT_API_BASE + "getOobConfirmationCode";
    when(mockSender.post(eq(expectedApiUrl), anyString(), eq(headers)))
        .thenReturn("{'otherThing':'fake-other-thing'}");

    try {
      GitkitClient.OobResponse oobResponse = gitkitClient.getOobResponse(mockRequest);
    } catch (GitkitServerException e) {
      assertTrue(e.getMessage().contains("{\"otherThing\":\"fake-other-thing\"}"));
    }
  }

  public void testGetOobCodeInvalidCaptchaCode() throws Exception {
    Cookie[] gitkitCookie = {new Cookie("gtoken", "fake-token")};
    HttpServletRequest mockRequest = Mockito.mock(HttpServletRequest.class);
    when(mockRequest.getCookies()).thenReturn(gitkitCookie);
    when(mockRequest.getParameter("action")).thenReturn("resetPassword");
    when(mockRequest.getParameter("email")).thenReturn("1111@example.com");
    when(mockRequest.getParameter("challenge")).thenReturn("what is the number");
    when(mockRequest.getParameter("response")).thenReturn("8888");
    when(mockRequest.getRemoteUser()).thenReturn("1.1.1.1");
    String expectedApiUrl = GitkitClient.GITKIT_API_BASE + "getOobConfirmationCode";
    when(mockSender.post(eq(expectedApiUrl), anyString(), eq(headers)))
        .thenReturn("{ \"error\": { \"code\": \"4xx\", \"message\": \"CAPTCHA_CHECK_FAILED\" }}");

    GitkitClient.OobResponse oobResponse = gitkitClient.getOobResponse(mockRequest);
    // the client collapses the error message down to a simple error:value
    assertEquals("{\"error\": \"CAPTCHA_CHECK_FAILED\" }", oobResponse.getResponseBody());
  }

  public void testGetEmailVerificationLink() throws Exception {
    String expectedApiUrl = GitkitClient.GITKIT_API_BASE + "getOobConfirmationCode";
    when(mockSender.post(eq(expectedApiUrl), anyString(), eq(headers)))
        .thenReturn("{'oobCode':'fake-oob-code'}");

    assertEquals(
        "http://example.com:80/gitkit?mode=verifyEmail&oobCode=fake-oob-code",
        gitkitClient.getEmailVerificationLink("user@example.com"));
  }
}

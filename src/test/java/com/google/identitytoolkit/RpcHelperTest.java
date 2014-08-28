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

import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

import com.google.common.collect.Maps;

import junit.framework.TestCase;

import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.Map;

/**
 * Test RpcHelper.
 */
public class RpcHelperTest extends TestCase {

  private static final String SERVICE_ACCOUNT_EMAIL = "dev@developer.gserviceaccount.com";
  private static final String API_URL = "http://localhost";
  private final HttpSender mockSender = Mockito.mock(HttpSender.class);
  private RpcHelper rpcHelper;

  @Override
  protected void setUp() {
    InputStream keyStream = new ByteArrayInputStream(TestConfig.getP12Key());
    rpcHelper = new RpcHelper(mockSender, API_URL, SERVICE_ACCOUNT_EMAIL, keyStream);
  }

  public void testGetAccessToken() throws Exception {
    Map<String, String> expectedHeader = Maps.newHashMap();
    expectedHeader.put("Content-Type", "application/x-www-form-urlencoded");
    when(mockSender.post(eq(RpcHelper.TOKEN_SERVER), anyString(), eq(expectedHeader)))
        .thenReturn("{'access_token': 'token'}");

    String result = rpcHelper.getAccessToken();

    assertEquals("token", result);
  }

  public void testGitkitClientError() throws Exception {
    String error = "{'error': {'code': 400, 'message': 'invalid email'}}";
    try {
      rpcHelper.checkGitkitException(error);
      fail();
    } catch (GitkitClientException e) {
      assertEquals("invalid email", e.getMessage());
    }
  }

  public void testGitkitServerError() throws Exception {
    try {
      rpcHelper.checkGitkitException("");
      fail();
    } catch (GitkitServerException e) {
      assertNotNull(e.getMessage());
    }
  }
}

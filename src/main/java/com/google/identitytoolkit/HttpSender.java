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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.Map;

/**
 * Default http sender for Gitkit.
 */
public class HttpSender {

  private static final String USER_AGENT = "GitkitJavaClient/1.0";
  private Proxy proxy = null;

  HttpSender() {}

  HttpSender(Proxy proxy) {
        this.proxy = proxy;
    }

  /**
   * Sends a HTTP Get request.
   *
   * @param url request url
   * @return http response content
   * @throws IOException
   */
  public String get(String url, Map<String, String> headers) throws IOException {
    return doHttpTransfer(url, null, headers);
  }

  /**
   * Sends a HTTP POST request.
   *
   * @param url request url
   * @param data json-encoded post body
   * @param headers http headers to send
   * @return content of the http response
   * @throws IOException
   */
  public String post(String url, String data, Map<String, String> headers) throws IOException {
    return doHttpTransfer(url, data, headers);
  }

  private String doHttpTransfer(String url, String data, Map<String, String> headers)
      throws IOException{
    try {
      HttpURLConnection connection;
      if(proxy == null)
        connection = (HttpURLConnection) new URL(url).openConnection();
      else
        connection = (HttpURLConnection) new URL(url).openConnection(proxy);

      for (Map.Entry<String, String> header : headers.entrySet()) {
        connection.setRequestProperty(header.getKey(), header.getValue());
      }
      connection.setRequestProperty("User-Agent", USER_AGENT);
      connection.setDoOutput(true);
      if (data != null) {
        connection.setRequestMethod("POST");
        OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream());
        writer.write(data);
        writer.close();
      } else {
        connection.setRequestMethod("GET");
      }

      InputStream inputStream = connection.getResponseCode() == 200
          ? connection.getInputStream()
          : connection.getErrorStream();
      BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
      StringBuilder response = new StringBuilder();
      String line;
      while ((line = reader.readLine()) != null) {
        response.append(line);
      }
      reader.close();
      return response.toString();
    } catch (MalformedURLException e) {
      throw new IOException(e);
    }
  }
}

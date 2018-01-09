/*
 * Copyright 2017 Red Hat, Inc. and/or its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.kie.server.controller.websocket.common.config;

public class WebSocketClientConfigurationImpl implements WebSocketClientConfiguration {

    private String controllerUrl;

    private String userName;

    private String token;

    private String password;

    private Long maxSessionIdleTimeout = 0L;

    protected WebSocketClientConfigurationImpl() {
    }

    @Override
    public String getControllerUrl() {
        return controllerUrl;
    }

    public void setControllerUrl(String controllerUrl) {
        this.controllerUrl = controllerUrl;
    }

    @Override
    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    @Override
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public Long getMaxSessionIdleTimeout() {
        return maxSessionIdleTimeout;
    }

    public void setMaxSessionIdleTimeout(Long maxSessionIdleTimeout) {
        this.maxSessionIdleTimeout = maxSessionIdleTimeout;
    }

    @Override
    public String toString() {
        return "WebSocketClientConfigurationImpl{" +
                "controllerUrl='" + controllerUrl + '\'' +
                ", userName='" + userName + '\'' +
                ", token='" + token + '\'' +
                ", password='" + password + '\'' +
                ", maxSessionIdleTimeout=" + maxSessionIdleTimeout +
                '}';
    }
}

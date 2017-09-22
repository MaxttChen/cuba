/*
 * Copyright (c) 2008-2017 Haulmont.
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

package com.haulmont.cuba.security.auth;

import com.haulmont.cuba.core.global.ClientType;

import java.util.Locale;
import java.util.Map;

public abstract class AbstractClientCredentials extends AbstractCredentials {
    private String clientInfo;
    private String address;
    private ClientType clientType;

    private boolean checkClientPermissions = true;

    public AbstractClientCredentials(Locale locale, Map<String, Object> params) {
        super(locale, params);
    }

    public AbstractClientCredentials() {
    }

    public String getClientInfo() {
        return clientInfo;
    }

    public void setClientInfo(String clientInfo) {
        this.clientInfo = clientInfo;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public ClientType getClientType() {
        return clientType;
    }

    public void setClientType(ClientType clientType) {
        this.clientType = clientType;
    }

    public boolean isCheckClientPermissions() {
        return checkClientPermissions;
    }

    public void setCheckClientPermissions(boolean checkClientPermissions) {
        this.checkClientPermissions = checkClientPermissions;
    }
}
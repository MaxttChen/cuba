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

package com.haulmont.cuba.security.authentication;

public class TrustedPasswordCredentials extends AbstractCredentials {

    private String trustedClientPassword;

    public String getTrustedClientPassword() {
        return trustedClientPassword;
    }

    public void setTrustedClientPassword(String trustedClientPassword) {
        this.trustedClientPassword = trustedClientPassword;
    }
}
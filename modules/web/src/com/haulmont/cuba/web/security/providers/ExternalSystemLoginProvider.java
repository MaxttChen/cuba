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

package com.haulmont.cuba.web.security.providers;

import com.haulmont.cuba.core.global.ClientType;
import com.haulmont.cuba.security.auth.AuthenticationDetails;
import com.haulmont.cuba.security.auth.AuthenticationService;
import com.haulmont.cuba.security.auth.Credentials;
import com.haulmont.cuba.security.auth.TrustedClientCredentials;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.web.auth.WebAuthConfig;
import com.haulmont.cuba.web.security.ExternalUserCredentials;
import com.haulmont.cuba.web.security.LoginProvider;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import javax.inject.Inject;

@Component("cuba_ExternalSystemLoginProvider")
public class ExternalSystemLoginProvider implements LoginProvider {
    @Inject
    protected AuthenticationService authenticationService;
    @Inject
    protected WebAuthConfig webAuthConfig;

    @Nullable
    @Override
    public AuthenticationDetails login(Credentials credentials) throws LoginException {
        ExternalUserCredentials externalUserCredentials = (ExternalUserCredentials) credentials;

        TrustedClientCredentials trustedClientCredentials = new TrustedClientCredentials(
                externalUserCredentials.getLogin(),
                webAuthConfig.getTrustedClientPassword(),
                externalUserCredentials.getLocale(),
                externalUserCredentials.getParams()
        );

        trustedClientCredentials.setClientInfo(externalUserCredentials.getClientInfo());
        trustedClientCredentials.setClientType(ClientType.WEB);
        trustedClientCredentials.setIpAddress(externalUserCredentials.getIpAddress());
        trustedClientCredentials.setOverrideLocale(externalUserCredentials.isOverrideLocale());
        trustedClientCredentials.setSyncNewUserSessionReplication(externalUserCredentials.isSyncNewUserSessionReplication());

        return authenticationService.login(trustedClientCredentials);
    }

    @Override
    public boolean supports(Class<?> credentialsClass) {
        return ExternalUserCredentials.class.isAssignableFrom(credentialsClass);
    }
}
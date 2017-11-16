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

import com.haulmont.cuba.security.auth.*;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.web.security.LoginProvider;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import javax.inject.Inject;

@Component("cuba_MiddlewareLoginProvider")
public class MiddlewareLoginProvider implements LoginProvider {
    @Inject
    protected AuthenticationService authenticationService;

    @Nullable
    @Override
    public AuthenticationDetails login(Credentials credentials) throws LoginException {
        return authenticationService.login(credentials);
    }

    @Override
    public boolean supports(Class<?> credentialsClass) {
        return LoginPasswordCredentials.class.isAssignableFrom(credentialsClass)
                || RememberMeCredentials.class.isAssignableFrom(credentialsClass);
    }
}
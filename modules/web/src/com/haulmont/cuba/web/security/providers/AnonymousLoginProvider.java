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

import com.haulmont.cuba.security.auth.AuthenticationDetails;
import com.haulmont.cuba.security.auth.Credentials;
import com.haulmont.cuba.security.auth.SimpleAuthenticationDetails;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.web.security.AnonymousUserCredentials;
import com.haulmont.cuba.web.security.LoginProvider;
import com.haulmont.cuba.web.security.WebAnonymousSessionHolder;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import javax.inject.Inject;

@Component("cuba_AnonymousLoginProvider")
public class AnonymousLoginProvider implements LoginProvider {
    @Inject
    protected WebAnonymousSessionHolder anonymousSessionHolder;

    @Nullable
    @Override
    public AuthenticationDetails login(Credentials credentials) throws LoginException {
        if (!(credentials instanceof AnonymousUserCredentials)) {
            throw new ClassCastException("Credentials cannot be cast to AnonymousUserCredentials");
        }

        return new SimpleAuthenticationDetails(anonymousSessionHolder.getAnonymousSession());
    }

    @Override
    public boolean supports(Class<?> credentialsClass) {
        return AnonymousUserCredentials.class.isAssignableFrom(credentialsClass);
    }
}
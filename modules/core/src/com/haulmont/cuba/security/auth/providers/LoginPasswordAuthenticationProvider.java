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

package com.haulmont.cuba.security.auth.providers;

import com.haulmont.cuba.core.Persistence;
import com.haulmont.cuba.core.global.Messages;
import com.haulmont.cuba.core.global.PasswordEncryption;
import com.haulmont.cuba.security.auth.*;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import com.haulmont.cuba.security.sys.UserSessionManager;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.util.List;
import java.util.Locale;

@Component("cuba_LoginPasswordAuthenticationProvider")
public class LoginPasswordAuthenticationProvider extends AbstractAuthenticationProvider {
    @Inject
    protected List<UserPermissionsChecker> userPermissionsCheckers;
    @Inject
    protected UserSessionManager userSessionManager;
    @Inject
    protected PasswordEncryption passwordEncryption;

    @Inject
    public LoginPasswordAuthenticationProvider(Persistence persistence, Messages messages) {
        super(persistence, messages);
    }

    @Override
    public UserSessionDetails authenticate(Credentials credentials) throws LoginException {
        LoginPasswordCredentials loginAndPassword = (LoginPasswordCredentials) credentials;

        String login = loginAndPassword.getLogin();

        Locale credentialsLocale = loginAndPassword.getLocale() == null ?
                messages.getTools().getDefaultLocale() : loginAndPassword.getLocale();

        User user = loadUser(login);
        if (user == null) {
            throw new LoginException(getInvalidCredentialsMessage(login, credentialsLocale));
        }

        if (!passwordEncryption.checkPassword(user, loginAndPassword.getPassword())) {
            throw new LoginException(getInvalidCredentialsMessage(login, credentialsLocale));
        }

        Locale userLocale = getUserLocale(loginAndPassword, user);

        UserSession session = userSessionManager.createSession(user, userLocale, false);

        setClientSessionParams(loginAndPassword, session);

        UserSessionDetails userSessionDetails = new SimpleUserSessionDetails(session);

        checkUserDetails(loginAndPassword, userSessionDetails);

        return userSessionDetails;
    }

    protected void checkUserDetails(Credentials loginAndPassword, UserSessionDetails userSessionDetails)
            throws LoginException {
        if (userPermissionsCheckers != null) {
            for (UserPermissionsChecker checker : userPermissionsCheckers) {
                checker.check(loginAndPassword, userSessionDetails);
            }
        }
    }

    @Override
    public boolean supports(Class<?> credentialsClass) {
        return LoginPasswordCredentials.class.isAssignableFrom(credentialsClass);
    }
}
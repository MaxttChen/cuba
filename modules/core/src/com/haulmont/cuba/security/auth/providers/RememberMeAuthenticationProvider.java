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

import com.haulmont.cuba.core.EntityManager;
import com.haulmont.cuba.core.Persistence;
import com.haulmont.cuba.core.TypedQuery;
import com.haulmont.cuba.core.global.Messages;
import com.haulmont.cuba.security.auth.*;
import com.haulmont.cuba.security.entity.RememberMeToken;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import com.haulmont.cuba.security.sys.UserSessionManager;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.util.List;
import java.util.Locale;

@Component("cuba_RememberMeAuthenticationProvider")
public class RememberMeAuthenticationProvider extends AbstractAuthenticationProvider implements Ordered {
    @Inject
    protected List<AccessChecker> accessCheckers;
    @Inject
    protected List<CredentialsChecker> credentialsCheckers;
    @Inject
    protected UserSessionManager userSessionManager;

    @Inject
    public RememberMeAuthenticationProvider(Persistence persistence, Messages messages) {
        super(persistence, messages);
    }

    @Override
    public UserSessionDetails authenticate(Credentials credentials) throws LoginException {
        checkCredentials(credentials);

        RememberMeCredentials rememberMe = (RememberMeCredentials) credentials;

        String login = rememberMe.getLogin();

        Locale credentialsLocale = rememberMe.getLocale() == null ?
                messages.getTools().getDefaultLocale() : rememberMe.getLocale();

        User user = loadUser(login);
        if (user == null) {
            throw new LoginException(getInvalidCredentialsMessage(login, credentialsLocale));
        }

        RememberMeToken loginToken = loadRememberMeToken(user, rememberMe.getRememberMeToken());
        if (loginToken == null) {
            throw new LoginException(getInvalidCredentialsMessage(login, credentialsLocale));
        }

        Locale userLocale = getUserLocale(rememberMe, user);

        UserSession session = userSessionManager.createSession(user, userLocale, false);

        setClientSessionParams(rememberMe, session);

        UserSessionDetails userSessionDetails = new SimpleUserSessionDetails(session);

        checkAccess(rememberMe, userSessionDetails);

        return userSessionDetails;
    }

    protected void checkCredentials(Credentials credentials) throws LoginException {
        if (credentialsCheckers != null) {
            for (CredentialsChecker checker : credentialsCheckers) {
                checker.check(credentials);
            }
        }
    }

    protected void checkAccess(Credentials loginAndPassword, UserSessionDetails userSessionDetails)
            throws LoginException {
        if (accessCheckers != null) {
            for (AccessChecker checker : accessCheckers) {
                checker.check(loginAndPassword, userSessionDetails);
            }
        }
    }

    @Nullable
    protected RememberMeToken loadRememberMeToken(User user, String rememberMeToken) {
        EntityManager em = persistence.getEntityManager();
        TypedQuery<RememberMeToken> query = em.createQuery(
                "select rt from sec$RememberMeToken rt where rt.token = :token and rt.user.id = :userId",
                RememberMeToken.class);
        query.setParameter("token", rememberMeToken);
        query.setParameter("userId", user.getId());

        return query.getFirstResult();
    }

    @Override
    public boolean supports(Class<?> credentialsClass) {
        return RememberMeCredentials.class.isAssignableFrom(credentialsClass);
    }

    @Override
    public int getOrder() {
        return HIGHEST_PLATFORM_PRECEDENCE + 20;
    }
}
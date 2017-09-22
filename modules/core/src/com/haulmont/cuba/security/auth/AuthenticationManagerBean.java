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

import com.haulmont.cuba.core.EntityManager;
import com.haulmont.cuba.core.Persistence;
import com.haulmont.cuba.core.Transaction;
import com.haulmont.cuba.core.TypedQuery;
import com.haulmont.cuba.core.global.Events;
import com.haulmont.cuba.core.global.MessageTools;
import com.haulmont.cuba.core.global.UserSessionSource;
import com.haulmont.cuba.security.auth.events.AuthenticationFailureEvent;
import com.haulmont.cuba.security.auth.events.AuthenticationSuccessEvent;
import com.haulmont.cuba.security.auth.events.UserLoggedOutEvent;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.NoUserSessionException;
import com.haulmont.cuba.security.global.UserSession;
import com.haulmont.cuba.security.sys.UserSessionManager;
import org.apache.commons.lang.LocaleUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import javax.persistence.NoResultException;
import java.util.List;
import java.util.Locale;

@Component(AuthenticationManager.NAME)
public class AuthenticationManagerBean implements AuthenticationManager {

    private final Logger log = LoggerFactory.getLogger(AuthenticationManagerBean.class);

    @Inject
    protected Events events;
    @Inject
    protected UserSessionSource userSessionSource;
    @Inject
    protected UserSessionManager userSessionManager;
    @Inject
    protected Persistence persistence;
    @Inject
    protected MessageTools messageTools;

    @Inject
    protected List<AuthenticationProvider> authenticationProviders;
    @Inject
    protected List<LoginConstraint> loginConstraints;

    @Override
    public UserSession login(Credentials credentials) throws LoginException {
        try (Transaction tx = persistence.getTransaction()) {
            // todo publish event

            UserDetails userDetails = authenticateInternal(credentials);
            User user = userDetails.getUser();

            // create session

            Locale userLocale = null;
            if (credentials instanceof LocalizedCredentials) {
                LocalizedCredentials localizedCredentials = (LocalizedCredentials) credentials;
                if (localizedCredentials.isOverrideLocale()) {
                    userLocale = localizedCredentials.getLocale();
                }
            }
            if (userLocale == null) {
                if (user.getLanguage() != null) {
                    userLocale = LocaleUtils.toLocale(user.getLanguage());
                } else {
                    userLocale = messageTools.getDefaultLocale();
                }
            }

            UserSession session = userSessionManager.createSession(userDetails.getUser(), userLocale, false);
            userSessionManager.clearPermissionsOnUser(session);
            if (loginConstraints != null) {
                for (LoginConstraint loginConstraint : loginConstraints) {
                    loginConstraint.checkLoginPermitted(credentials, userDetails, session);
                }
            }

            // todo publish event

            tx.commit();

            // store session

            return null;
        }
    }

    @Override
    public UserDetails authenticate(Credentials credentials) throws LoginException {
        try (Transaction tx = persistence.getTransaction()) {
            UserDetails userDetails = authenticateInternal(credentials);

            tx.commit();

            return userDetails;
        }
    }

    @Override
    public void logout() {
        try {
            UserSession session = userSessionSource.getUserSession();
            userSessionManager.removeSession(session);
            log.info("Logged out: {}", session);

            publishUserLoggedOut(session);

        } catch (SecurityException e) {
            log.warn("Couldn't logout: {}", e);
        } catch (NoUserSessionException e) {
            log.warn("NoUserSessionException thrown on logout");
        }
    }

    @Override
    public UserSession substituteUser(User substitutedUser) {
        UserSession currentSession = userSessionSource.getUserSession();

        try (Transaction tx = persistence.createTransaction()) {
            EntityManager em = persistence.getEntityManager();

            User user;
            if (currentSession.getUser().equals(substitutedUser)) {
                user = em.find(User.class, substitutedUser.getId());
                if (user == null)
                    throw new NoResultException("User not found");
            } else {
                TypedQuery<User> query = em.createQuery(
                        "select s.substitutedUser from sec$User u join u.substitutions s " +
                                "where u.id = ?1 and s.substitutedUser.id = ?2",
                        User.class
                );
                query.setParameter(1, currentSession.getUser());
                query.setParameter(2, substitutedUser);
                List<User> list = query.getResultList();
                if (list.isEmpty())
                    throw new NoResultException("User not found");
                else
                    user = list.get(0);
            }

            UserSession session = userSessionManager.createSession(currentSession, user);

            // todo publish event

            tx.commit();

            userSessionManager.removeSession(currentSession);
            userSessionManager.clearPermissionsOnUser(session);
            userSessionManager.storeSession(session);

            return session;
        }
    }

    protected UserDetails authenticateInternal(Credentials credentials) throws LoginException {
        Class<? extends Credentials> credentialsClass = credentials.getClass();

        for (AuthenticationProvider provider : getProviders()) {
            if (!provider.supports(credentialsClass)) {
                continue;
            }

            log.debug("Authentication attempt using {}", provider.getClass().getName());

            try {
                UserDetails details = provider.authenticate(credentials);

                if (details != null) {
                    log.debug("Authentication successful for {}", credentials);

                    // publish auth success
                    publishAuthenticationSuccess(details, credentials);

                    return details;
                }
            } catch (LoginException e) {
                // publish auth fail
                publishAuthenticationFailed(provider, credentials);

                throw e;
            }
        }

        throw new NoAuthenticationProviderException(
                "Unable to find authentication provider that supports credentials class "
                        + credentialsClass.getName());
    }

    protected void publishAuthenticationFailed(AuthenticationProvider provider, Credentials credentials) {
        events.publish(new AuthenticationFailureEvent(credentials, provider));
    }

    protected void publishAuthenticationSuccess(UserDetails details, Credentials credentials) {
        events.publish(new AuthenticationSuccessEvent(credentials, details));
    }

    protected void publishUserLoggedOut(UserSession session) {
        events.publish(new UserLoggedOutEvent(session));
    }

    public List<AuthenticationProvider> getProviders() {
        return authenticationProviders;
    }
}
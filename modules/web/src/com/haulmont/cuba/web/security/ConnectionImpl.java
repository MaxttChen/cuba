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

package com.haulmont.cuba.web.security;

import com.haulmont.bali.events.EventRouter;
import com.haulmont.cuba.client.ClientUserSession;
import com.haulmont.cuba.core.global.ClientType;
import com.haulmont.cuba.core.global.Events;
import com.haulmont.cuba.core.global.GlobalConfig;
import com.haulmont.cuba.core.global.Messages;
import com.haulmont.cuba.core.sys.AppContext;
import com.haulmont.cuba.security.app.UserSessionService;
import com.haulmont.cuba.security.auth.AbstractClientCredentials;
import com.haulmont.cuba.security.auth.AuthenticationDetails;
import com.haulmont.cuba.security.auth.AuthenticationService;
import com.haulmont.cuba.security.auth.Credentials;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.*;
import com.haulmont.cuba.web.Connection;
import com.vaadin.server.VaadinSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.util.List;

/**
 * Default {@link Connection} implementation for web-client.
 */
@Component(Connection.NAME)
@Scope(BeanDefinition.SCOPE_PROTOTYPE)
public class ConnectionImpl extends EventRouter implements Connection {

    private static final Logger log = LoggerFactory.getLogger(ConnectionImpl.class);

    protected boolean connected;

    @Inject
    private AuthenticationService authenticationService;
    @Inject
    protected UserSessionService userSessionService;
    @Inject
    protected List<LoginProvider> loginProviders;

    @Inject
    protected Events events;
    @Inject
    protected Messages messages;
    @Inject
    protected GlobalConfig globalConfig;

    protected ClientUserSession session;

    @Override
    public void login(Credentials credentials) throws LoginException {
        preprocessCredentials(credentials);

        AuthenticationDetails authenticationDetails = loginInternal(credentials);

        // todo
    }

    protected void preprocessCredentials(Credentials credentials) {
        if (credentials instanceof AbstractClientCredentials) {
            ((AbstractClientCredentials) credentials).setClientType(ClientType.WEB);
        }
    }

    protected AuthenticationDetails loginInternal(Credentials credentials) throws LoginException {
        publishBeforeLoginEvent(credentials);

        Class<? extends Credentials> credentialsClass = credentials.getClass();

        AuthenticationDetails details = null;
        try {
            for (LoginProvider provider : getProviders()) {
                if (!provider.supports(credentialsClass)) {
                    continue;
                }

                log.debug("Login attempt using {}", provider.getClass().getName());

                try {
                    details = provider.login(credentials);

                    if (details != null) {
                        log.debug("Login successful for {}", credentials);

                        // publish login success
                        publishLoginSuccess(details, credentials);

                        return details;
                    }
                } catch (LoginException e) {
                    // publish auth fail
                    publishLoginFailed(credentials, provider, e);

                    throw e;
                } catch (RuntimeException re) {
                    InternalAuthenticationException ie =
                            new InternalAuthenticationException("Exception is thrown by authentication provider", re);

                    // publish auth fail
                    publishLoginFailed(credentials, provider, ie);

                    throw ie;
                }
            }
        } finally {
            publishAfterLoginEvent(credentials, details);
        }

        throw new UnsupportedCredentialsException(
                "Unable to find login provider that supports credentials class "
                        + credentialsClass.getName());
    }

    protected void publishBeforeLoginEvent(Credentials credentials) {
        // todo
    }

    protected void publishAfterLoginEvent(Credentials credentials, AuthenticationDetails details) {
        // todo
    }

    protected void publishLoginFailed(Credentials credentials, LoginProvider provider, LoginException e) {
        // todo
    }

    protected void publishLoginSuccess(AuthenticationDetails details, Credentials credentials) {
        // todo
    }

    @Override
    public void logout() {
        if (session == null) {
            throw new IllegalStateException("There is no active session");
        }
        if (!session.isAuthenticated()) {
            throw new IllegalStateException("Active session is not authenticated");
        }

        authenticationService.logout();

        AppContext.setSecurityContext(null);

        StateChangeEvent event = new StateChangeEvent(this);
        fireEvent(StateChangeListener.class, StateChangeListener::connectionStateChanged, event);

        removeListeners(UserSubstitutionListener.class);
    }

    @Override
    @Nullable
    public UserSession getSession() {
        return VaadinSession.getCurrent().getAttribute(UserSession.class);
    }

    @Override
    public void substituteUser(User substitutedUser) {
        // todo
    }

    @Override
    public boolean isConnected() {
        return connected;
    }

    @Override
    public boolean isAuthenticated() {
        if (!connected) {
            return false;
        }

        UserSession session = getSession();
        return session instanceof ClientUserSession
                && ((ClientUserSession) session).isAuthenticated();
    }

    protected void setSession(ClientUserSession clientUserSession) {
        VaadinSession.getCurrent().setAttribute(UserSession.class, clientUserSession);
    }

    @Override
    public boolean isAlive() {
        if (!isConnected()) {
            return false;
        }

        UserSession session = getSession();
        if (session == null) {
            return false;
        }

        try {
            userSessionService.getUserSession(session.getId());
        } catch (NoUserSessionException ignored) {
            return false;
        }

        return true;
    }

    @Override
    public void addStateChangeListener(StateChangeListener listener) {
        addListener(StateChangeListener.class, listener);
    }

    @Override
    public void removeStateChangeListener(StateChangeListener listener) {
        removeListener(StateChangeListener.class, listener);
    }

    @Override
    public void addUserSubstitutionListener(UserSubstitutionListener listener) {
        addListener(UserSubstitutionListener.class, listener);
    }

    @Override
    public void removeUserSubstitutionListener(UserSubstitutionListener listener) {
        removeListener(UserSubstitutionListener.class, listener);
    }

    protected List<LoginProvider> getProviders() {
        return loginProviders;
    }

    @Override
    public String logoutExternalAuthentication() {
        return null; // todo
    }
}
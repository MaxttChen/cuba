/*
 * Copyright (c) 2008-2016 Haulmont.
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
 *
 */
package com.haulmont.cuba.security.app;

import com.haulmont.cuba.core.global.UserSessionSource;
import com.haulmont.cuba.security.authentication.Credentials;
import com.haulmont.cuba.security.authentication.UserDetails;
import com.haulmont.cuba.security.entity.SessionAction;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import org.apache.commons.lang.NotImplementedException;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.util.Collections;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/**
 * Service to provide methods for user login/logout to the middleware.
 */
@Component(LoginService.NAME)
public class LoginServiceBean implements LoginService {

    private final Logger log = LoggerFactory.getLogger(LoginServiceBean.class);

    @Inject
    protected LoginWorker loginWorker;

    @Inject
    protected UserSessionSource userSessionSource;

    @Inject
    protected BruteForceProtectionAPI bruteForceProtectionAPI;

    @Inject
    protected UserSessionLog userSessionLog;

    @Override
    public UserSession login(Credentials credentials) throws LoginException {
        try {
            return loginWorker.login(credentials);
        } catch (LoginException e) {
            log.info("Login failed: {}", e.toString());
            throw e;
        } catch (Throwable e) {
            log.error("Login error", e);
            throw wrapInLoginException(e);
        }
    }

    @Override
    public UserDetails authenticate(Credentials credentials) throws LoginException {
        try {
            return loginWorker.authenticate(credentials);
        } catch (LoginException e) {
            log.info("Login failed: {}", e.toString());
            throw e;
        } catch (Throwable e) {
            log.error("Login error", e);
            throw wrapInLoginException(e);
        }
    }

    @Override
    public UserSession login(String login, String password, Locale locale) throws LoginException {
        return login(login, password, locale, Collections.emptyMap());
    }

    @Override
    public UserSession login(String login, String password, Locale locale, Map<String, Object> params) throws LoginException {
        try {
            UserSession session = loginWorker.login(login, password, locale, params);
            userSessionLog.createSessionLogRecord(session, SessionAction.LOGIN, params);
            return session;
        } catch (LoginException e) {
            log.info("Login failed: {}", e.toString());
            throw e;
        } catch (Throwable e) {
            log.error("Login error", e);
            throw wrapInLoginException(e);
        }
    }

    @Override
    public UserSession loginTrusted(String login, String password, Locale locale) throws LoginException {
        return loginTrusted(login, password, locale, Collections.emptyMap());
    }

    @Override
    public UserSession loginTrusted(String login, String password, Locale locale, Map<String, Object> params) throws LoginException {
        try {
            UserSession session = loginWorker.loginTrusted(login, password, locale, params);
            userSessionLog.createSessionLogRecord(session, SessionAction.LOGIN, params);
            return session;
        } catch (LoginException e) {
            log.info("Login failed: {}", e.toString());
            throw e;
        } catch (Throwable e) {
            log.error("Login error", e);
            throw wrapInLoginException(e);
        }
    }

    @Override
    public UserSession loginByRememberMe(String login, String rememberMeToken, Locale locale) throws LoginException {
        return loginByRememberMe(login, rememberMeToken, locale, Collections.emptyMap());
    }

    @Override
    public UserSession loginByRememberMe(String login, String rememberMeToken, Locale locale, Map<String, Object> params)
            throws LoginException {
        try {
            UserSession session = loginWorker.loginByRememberMe(login, rememberMeToken, locale, params);
            userSessionLog.createSessionLogRecord(session, SessionAction.LOGIN, params);
            return session;
        } catch (LoginException e) {
            log.info("Login failed: {}", e.toString());
            throw e;
        } catch (Throwable e) {
            log.error("Login error", e);
            throw wrapInLoginException(e);
        }
    }

    @Override
    public UserSession getSystemSession(String trustedClientPassword) throws LoginException {
        try {
            return loginWorker.getSystemSession(trustedClientPassword);
        } catch (LoginException e) {
            log.info("Login failed: {}", e.toString());
            throw e;
        } catch (Throwable e) {
            log.error("Login error", e);
            throw wrapInLoginException(e);
        }
    }

    @Override
    public UserSession getAnonymousSession(String trustedClientPassword) throws LoginException {
        throw new NotImplementedException(""); // todo
    }

    @Override
    public void logout() {
        try {
            UserSession session = userSessionSource.getUserSession();

            if (session != null && session.isSystem()) {
                throw new RuntimeException("Logout of system session from client is not permitted");
            }

            userSessionLog.updateSessionLogRecord(session, SessionAction.LOGOUT);

            loginWorker.logout();
            userSessionLog.updateSessionLogRecord(session, SessionAction.LOGOUT);
        } catch (Throwable e) {
            log.error("Logout error", e);
            throw new RuntimeException(e.toString());
        }
    }

    @Override
    public UserSession substituteUser(User substitutedUser) {
        UserSession currentSession = userSessionSource.getUserSession();
        userSessionLog.updateSessionLogRecord(currentSession, SessionAction.SUBSTITUTION);

        UserSession substitutionSession = loginWorker.substituteUser(substitutedUser);

        userSessionLog.createSessionLogRecord(substitutionSession, SessionAction.LOGIN, currentSession, Collections.emptyMap());
        return substitutionSession;
    }

    @Override
    public UserSession getSession(UUID sessionId) {
        return loginWorker.getSession(sessionId);
    }

    @Override
    public boolean checkRememberMe(String login, String rememberMeToken) {
        return false;
    }

    protected LoginException wrapInLoginException(Throwable throwable) {
        //noinspection ThrowableResultOfMethodCallIgnored
        Throwable rootCause = ExceptionUtils.getRootCause(throwable);
        if (rootCause == null)
            rootCause = throwable;
        // send text only to avoid ClassNotFoundException when the client has no dependency to some library
        return new LoginException(rootCause.toString());
    }

    @Override
    public boolean isBruteForceProtectionEnabled() {
        return bruteForceProtectionAPI.isBruteForceProtectionEnabled();
    }

    @Override
    public int getBruteForceBlockIntervalSec() {
        return bruteForceProtectionAPI.getBruteForceBlockIntervalSec();
    }

    @Override
    public int loginAttemptsLeft(String login, String ipAddress) {
        return bruteForceProtectionAPI.loginAttemptsLeft(login, ipAddress);
    }

    @Override
    public int registerUnsuccessfulLogin(String login, String ipAddress) {
        return bruteForceProtectionAPI.registerUnsuccessfulLogin(login, ipAddress);
    }
}
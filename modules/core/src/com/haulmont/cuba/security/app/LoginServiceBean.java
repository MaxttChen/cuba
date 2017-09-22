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

import com.haulmont.cuba.security.auth.AuthenticationService;
import com.haulmont.cuba.security.auth.LoginPasswordCredentials;
import com.haulmont.cuba.security.auth.RememberMeCredentials;
import com.haulmont.cuba.security.auth.TrustedClientCredentials;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
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
@Deprecated
public class LoginServiceBean implements LoginService {

    private final Logger log = LoggerFactory.getLogger(LoginServiceBean.class);

    @Inject
    protected AuthenticationService authenticationService;

    @Inject
    protected LoginWorker loginWorker;

    @Inject
    protected BruteForceProtectionAPI bruteForceProtectionAPI;

    @Override
    public UserSession login(String login, String password, Locale locale) throws LoginException {
        return login(login, password, locale, Collections.emptyMap());
    }

    @Override
    public UserSession login(String login, String password, Locale locale, Map<String, Object> params) throws LoginException {
        LoginPasswordCredentials credentials = new LoginPasswordCredentials(login, password, locale, params);
        return authenticationService.login(credentials);
    }

    @Override
    public UserSession loginTrusted(String login, String password, Locale locale) throws LoginException {
        return loginTrusted(login, password, locale, Collections.emptyMap());
    }

    @Override
    public UserSession loginTrusted(String login, String password, Locale locale, Map<String, Object> params) throws LoginException {
        TrustedClientCredentials credentials = new TrustedClientCredentials(login, password, locale, params);
        return authenticationService.login(credentials);
    }

    @Override
    public UserSession loginByRememberMe(String login, String rememberMeToken, Locale locale) throws LoginException {
        return loginByRememberMe(login, rememberMeToken, locale, Collections.emptyMap());
    }

    @Override
    public UserSession loginByRememberMe(String login, String rememberMeToken, Locale locale, Map<String, Object> params)
            throws LoginException {
        RememberMeCredentials credentials = new RememberMeCredentials(login, rememberMeToken, locale, params);
        return authenticationService.login(credentials);
    }

    @Override
    public UserSession getSystemSession(String trustedClientPassword) throws LoginException {
        try {
            // todo move to TrustedClientService
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
    public void logout() {
        authenticationService.logout();
    }

    @Override
    public UserSession substituteUser(User substitutedUser) {
        return authenticationService.substituteUser(substitutedUser);
    }

    @Override
    public UserSession getSession(UUID sessionId) {
        return loginWorker.getSession(sessionId);
    }

    @Override
    public boolean checkRememberMe(String login, String rememberMeToken) {
        log.warn("LoginService checkRememberMe is not supported any more. Always returns false");
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
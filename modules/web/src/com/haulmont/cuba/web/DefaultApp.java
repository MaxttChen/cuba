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
package com.haulmont.cuba.web;

import com.google.common.base.Strings;
import com.haulmont.bali.util.ParamsMap;
import com.haulmont.cuba.core.global.UserSessionSource;
import com.haulmont.cuba.gui.WindowManager.OpenType;
import com.haulmont.cuba.gui.components.Window;
import com.haulmont.cuba.gui.config.WindowInfo;
import com.haulmont.cuba.security.auth.TrustedClientCredentials;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import com.haulmont.cuba.web.app.loginwindow.AppLoginWindow;
import com.haulmont.cuba.web.auth.ExternalAuthenticationSettingsHelper;
import com.haulmont.cuba.web.auth.IdpAuthProvider;
import com.vaadin.server.*;
import com.vaadin.ui.UI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Scope;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Locale;

/**
 * Default {@link App} implementation that shows {@link AppLoginWindow} on start.
 * Supports SSO through external authentication.
 */
@Component(App.NAME)
@Scope(BeanDefinition.SCOPE_PROTOTYPE)
public class DefaultApp extends App implements ConnectionListener, UserSubstitutionListener {

    private static final Logger log = LoggerFactory.getLogger(DefaultApp.class);

    // Login on start only on first request from user
    protected boolean tryLoginOnStart = true;

    @Inject
    protected UserSessionSource userSessionSource;

    @Inject
    protected IdpAuthProvider idpAuthProvider;

    @Inject
    protected ExternalAuthenticationSettingsHelper externalAuthenticationSettingsHelper;

    public DefaultApp() {
    }

    @Override
    protected Connection createConnection() {
        Connection connection = super.createConnection();
        connection.addConnectionListener(this);
        return connection;
    }

    @Override
    public void connectionStateChanged(Connection connection) throws LoginException {
        log.debug("connectionStateChanged connected: {}, authenticated: {}",
                connection.isConnected(), connection.isAuthenticated());

        cleanupBackgroundTasks();
        closeAllWindows();
        clearSettingsCache();

        if (connection.isConnected()) {
            UserSession userSession = connection.getSession();
            if (userSession == null) {
                throw new IllegalStateException("Unable to obtain session from connected Connection");
            }
            setLocale(userSession.getLocale());

            // substitution listeners are cleared by connection on logout
            connection.addSubstitutionListener(this);

            if (isReinitializeSession()) {
                VaadinService.reinitializeSession(VaadinService.getCurrentRequest());

                WrappedSession session = VaadinSession.getCurrent().getSession();
                int timeout = webConfig.getHttpSessionExpirationTimeoutSec();
                session.setMaxInactiveInterval(timeout);

                HttpSession httpSession = session instanceof WrappedHttpSession ?
                        ((WrappedHttpSession) session).getHttpSession() : null;
                log.debug("Session reinitialized: HttpSession={}, timeout={}sec, UserSession={}",
                        httpSession, timeout, connection.getSession());
            }

            initExceptionHandlers(true);

            AppUI currentUi = AppUI.getCurrent();
            if (currentUi != null) {
                createTopLevelWindow(currentUi);
            }

            for (AppUI ui : getAppUIs()) {
                if (currentUi != ui) {
                    ui.accessSynchronously(() ->
                            createTopLevelWindow(ui)
                    );
                }
            }

            if (linkHandler != null && linkHandler.canHandleLink()) {
                linkHandler.handle();
                linkHandler = null;
            }

            afterLoggedIn();
        } else {
            boolean redirectedToExternalAuth = false;

            if (externalAuthenticationSettingsHelper.isIdpUsed()) {
                String loggedOutUrl = idpAuthProvider.logout();

                if (!Strings.isNullOrEmpty(loggedOutUrl)) {
                    AppUI currentUi = AppUI.getCurrent();
                    // it can be null if we handle request in a custom RequestHandler
                    if (currentUi != null) {
                        currentUi.setContent(null);
                        currentUi.getPage().setLocation(loggedOutUrl);
                    } else {
                        VaadinResponse response = VaadinService.getCurrentResponse();
                        try {
                            ((VaadinServletResponse) response).getHttpServletResponse().
                                    sendRedirect(loggedOutUrl);
                        } catch (IOException e) {
                            log.error("Error on send redirect to client", e);
                        }
                    }

                    VaadinSession vaadinSession = VaadinSession.getCurrent();
                    for (UI ui : vaadinSession.getUIs()) {
                        if (ui != currentUi) {
                            ui.access(() -> {
                                ui.setContent(null);
                                ui.getPage().setLocation(loggedOutUrl);
                            });
                        }
                    }

                    redirectedToExternalAuth = true;
                }
            }

            if (!redirectedToExternalAuth) {
                initExceptionHandlers(false);

                Locale requestLocale = VaadinService.getCurrentRequest().getLocale();
                setLocale(resolveLocale(requestLocale));

                getConnection().loginAnonymous(getLocale());
            }
        }
    }

    @Override
    protected String routeTopLevelWindowId() {
        if (connection.isAuthenticated()) {
            return "mainWindow";
        } else {
            return "loginWindow";
        }
    }

    /**
     * Perform actions after successful login
     */
    protected void afterLoggedIn() {
        if (isChangePasswordAtNextLogin()) {

            WebWindowManager wm = getWindowManager();
            for (Window window : wm.getOpenWindows()) {
                window.setEnabled(false);
            }

            WindowInfo changePasswordDialog = windowConfig.getWindowInfo("sec$User.changePassword");

            Window changePasswordWindow = wm.openWindow(changePasswordDialog,
                    OpenType.DIALOG.closeable(false),
                    ParamsMap.of("cancelEnabled", Boolean.FALSE));

            changePasswordWindow.addCloseListener(actionId -> {
                for (Window window : wm.getOpenWindows()) {
                    window.setEnabled(true);
                }
            });
        }
    }

    @Override
    public boolean loginOnStart() {
        if (isLoginOnStart()) {

            String userName = principal.getName();
            log.debug("Trying to login after external authentication as {}", userName);
            try {

                connection.login(
                        new TrustedClientCredentials(userName, webAuthConfig.getTrustedClientPassword(), getLocale())
                );

                UserSession session = getConnection().getSession();
                idpAuthProvider.userSessionLoggedIn(session);

                return true;
            } catch (LoginException e) {
                log.trace("Unable to login on start", e);
            } finally {
                // Close attempt login on start
                tryLoginOnStart = false;
            }
        }

        return false;
    }

    @Override
    public void userSubstituted(Connection connection) {
        cleanupBackgroundTasks();
        clearSettingsCache();
        closeAllWindows();

        AppUI currentUi = AppUI.getCurrent();
        // it can be null if we came from a custom Vaadin RequestHandler
        if (currentUi != null) {
            createTopLevelWindow(currentUi);
        }

        for (AppUI ui : getAppUIs()) {
            if (currentUi != ui) {
                ui.accessSynchronously(() ->
                        createTopLevelWindow(ui)
                );
            }
        }
    }

    protected boolean isChangePasswordAtNextLogin() {
        if (connection.isAuthenticated() && !externalAuthenticationSettingsHelper.isIdpOrLdapUsed()) {

            User user = userSessionSource.getUserSession().getUser();

            return Boolean.TRUE.equals(user.getChangePasswordAtNextLogon());

        } else {
            return false;
        }
    }

    protected boolean isReinitializeSession() {
        return connection.isAuthenticated()
                && !externalAuthenticationSettingsHelper.isIdpUsed()
                && webConfig.getUseSessionFixationProtection();
    }

    protected boolean isLoginOnStart() {
        return tryLoginOnStart
                && principal != null
                && externalAuthenticationSettingsHelper.isIdpUsed();
    }
}
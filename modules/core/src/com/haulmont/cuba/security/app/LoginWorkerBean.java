/*
 * Copyright (c) 2008 Haulmont Technology Ltd. All Rights Reserved.
 * Haulmont Technology proprietary and confidential.
 * Use is subject to license terms.

 * Author: Konstantin Krivopustov
 * Created: 26.11.2008 14:06:47
 *
 * $Id$
 */
package com.haulmont.cuba.security.app;

import com.haulmont.cuba.core.*;
import com.haulmont.cuba.core.global.MessageProvider;
import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.NoUserSessionException;
import com.haulmont.cuba.security.global.UserSession;
import com.haulmont.cuba.security.sys.UserSessionManager;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.ejb.Stateless;
import java.util.List;
import java.util.Locale;

/**
 * Worker bean providing middleware login/logout functionality.
 * Used by {@link com.haulmont.cuba.security.app.LoginServiceBean} and MBeans
 */
@Stateless(name = LoginWorker.JNDI_NAME)
public class LoginWorkerBean implements LoginWorker
{
    private Log log = LogFactory.getLog(LoginWorkerBean.class);

    private User loadUser(String login, String password, Locale locale)
            throws LoginException
    {
        if (login == null)
            throw new IllegalArgumentException("Login is null");

        EntityManager em = PersistenceProvider.getEntityManager();
        String queryStr = "select u from sec$User u where u.loginLowerCase = ?1";
        if (password != null)
            queryStr += " and u.password = ?2";

        Query q = em.createQuery(queryStr);
        q.setParameter(1, login.toLowerCase());
        if (password != null)
            q.setParameter(2, password);

        List list = q.getResultList();
        if (list.isEmpty()) {
            log.warn("Failed to authenticate: " + login);
            if (password != null)
                throw new LoginException(
                        String.format(MessageProvider.getMessage(getClass(), "LoginException.InvalidLoginOrPassword", locale),
                                login));
            else
                throw new LoginException(
                        String.format(MessageProvider.getMessage(getClass(), "LoginException.InvalidActiveDirectoryUser", locale),
                                login));
        }
        else {
            User user = (User) list.get(0);
            return user;
        }
    }

    public UserSession login(String login, String password, Locale locale)
            throws LoginException
    {
        User user = loadUser(login, password, locale);
        UserSession session = UserSessionManager.getInstance().createSession(user, locale);
        if (user.getDefaultSubstitutedUser() != null) {
            UserSessionManager.getInstance().updateSession(session, user.getDefaultSubstitutedUser());
        }
        log.info("Logged in: " + session);
        return session;
    }

    public UserSession loginActiveDirectory(String login, Locale locale) throws LoginException {
        User user = loadUser(login, null, locale);
        UserSession session = UserSessionManager.getInstance().createSession(user, locale);
        if (user.getDefaultSubstitutedUser() != null) {
            UserSessionManager.getInstance().updateSession(session, user.getDefaultSubstitutedUser());
        }
        log.info("Logged in: " + session);
        return session;
    }

    public void logout() {
        try {
            UserSession session = SecurityProvider.currentUserSession();
            UserSessionManager.getInstance().removeSession(session);
            log.info("Logged out: " + session);
        } catch (NoUserSessionException e) {
            log.warn("NoUserSessionException thrown on logout");
        }
    }

    public UserSession substituteUser(User substitutedUser) {
        UserSession currentSession = SecurityProvider.currentUserSession();

        Transaction tx = Locator.createTransaction();
        try {
            EntityManager em = PersistenceProvider.getEntityManager();
            User user = em.find(User.class, substitutedUser.getId());

            UserSession session = UserSessionManager.getInstance().updateSession(currentSession, user);

            tx.commit();

            return session;
        } finally {
            tx.end();
        }
    }

    public void ping() {
    }
}

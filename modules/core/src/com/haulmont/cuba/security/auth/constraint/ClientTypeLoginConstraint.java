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

package com.haulmont.cuba.security.auth.constraint;

import com.haulmont.cuba.core.global.ClientType;
import com.haulmont.cuba.security.auth.AbstractClientCredentials;
import com.haulmont.cuba.security.auth.Credentials;
import com.haulmont.cuba.security.auth.LoginConstraint;
import com.haulmont.cuba.security.auth.UserDetails;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component("cuba_ClientLoginConstraint")
public class ClientTypeLoginConstraint implements LoginConstraint {

    private final Logger log = LoggerFactory.getLogger(ClientTypeLoginConstraint.class);

    @Override
    public void checkLoginPermitted(Credentials credentials, UserDetails userDetails, UserSession session)
            throws LoginException {

        if (credentials instanceof AbstractClientCredentials) {
            AbstractClientCredentials clientCredentials = (AbstractClientCredentials) credentials;

            if (clientCredentials.isCheckClientPermissions()) {
                ClientType clientType = clientCredentials.getClientType();

                if (ClientType.DESKTOP == clientType || ClientType.WEB == clientType) {
                    if (!session.isSpecificPermitted("cuba.gui.loginToClient")) {
                        log.warn("Attempt of login to {} for user '{}' without cuba.gui.loginToClient permission",
                                clientType, clientCredentials);

//                        throw new LoginException(getInvalidCredentialsMessage(login, userLocale));
                    }
                }
            }
        }
    }
}
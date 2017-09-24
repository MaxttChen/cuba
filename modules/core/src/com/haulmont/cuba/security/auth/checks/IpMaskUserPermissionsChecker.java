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

package com.haulmont.cuba.security.auth.checks;

import com.haulmont.cuba.core.global.Messages;
import com.haulmont.cuba.security.auth.AbstractClientCredentials;
import com.haulmont.cuba.security.auth.Credentials;
import com.haulmont.cuba.security.auth.UserSessionDetails;
import com.haulmont.cuba.security.global.IpMatcher;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.inject.Inject;

@Component("cuba_IpMaskLoginConstraint")
public class IpMaskUserPermissionsChecker extends AbstractUserPermissionsChecker {

    private final Logger log = LoggerFactory.getLogger(IpMaskUserPermissionsChecker.class);

    @Inject
    public IpMaskUserPermissionsChecker(Messages messages) {
        super(messages);
    }

    @Override
    public void check(Credentials credentials, UserSessionDetails userSessionDetails) throws LoginException {
        if (credentials instanceof AbstractClientCredentials) {
            AbstractClientCredentials clientCredentials = (AbstractClientCredentials) credentials;

            if (clientCredentials.isCheckClientPermissions()) {
                String ipAddress = clientCredentials.getIpAddress();

                UserSession session = userSessionDetails.getSession();

                IpMatcher ipMatcher = new IpMatcher(session.getUser().getIpMask());
                if (!ipMatcher.match(ipAddress)) {
                    log.info("IP address {} is not permitted for user {}", ipAddress, session.getUser());

                    throw new LoginException(messages.getMessage(MSG_PACK, "LoginException.invalidIP"));
                }
            }
        }
    }
}
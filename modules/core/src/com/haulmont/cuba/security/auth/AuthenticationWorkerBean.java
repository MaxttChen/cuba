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

import com.haulmont.cuba.security.entity.User;
import com.haulmont.cuba.security.global.LoginException;
import com.haulmont.cuba.security.global.UserSession;
import org.springframework.stereotype.Component;

@Component(AuthenticationWorker.NAME)
public class AuthenticationWorkerBean implements AuthenticationWorker {
    @Override
    public UserSession login(Credentials credentials) throws LoginException {
        return null;
    }

    @Override
    public UserDetails authenticate(Credentials credentials) throws LoginException {
        return null;
    }

    @Override
    public void logout() {

    }

    @Override
    public UserSession substituteUser(User substitutedUser) {
        return null;
    }
}
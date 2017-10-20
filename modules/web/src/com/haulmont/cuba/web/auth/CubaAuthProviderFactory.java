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

package com.haulmont.cuba.web.auth;

import com.haulmont.cuba.core.global.Configuration;
import org.springframework.context.ApplicationContext;

import org.springframework.stereotype.Component;
import javax.inject.Inject;

/**
 * @deprecated
 * Injects custom {@link CubaAuthProvider}.
 * Please use {@link com.haulmont.cuba.web.sys.filter.CubaFilter} or {@link com.haulmont.cuba.web.auth.provider.LoginProvider}
 *  to implement your custom login logic.
 * Scheduled to be removed in CUBA 7.0
 */
@Deprecated
@Component("cuba_AuthProviderFactory")
public class CubaAuthProviderFactory {

    @Inject
    protected Configuration configuration;

    @Inject
    private ApplicationContext applicationContext;

    public CubaAuthProvider createAuthProvider() {
        WebAuthConfig authConfig = configuration.getConfig(WebAuthConfig.class);
        String providerClassName = authConfig.getExternalAuthenticationProviderClass();

        try {
            ClassLoader classLoader = applicationContext.getClassLoader();
            Class<?> providerClass = classLoader.loadClass(providerClassName);
            CubaAuthProvider cubaAuthProvider = (CubaAuthProvider) providerClass.newInstance();
            return cubaAuthProvider;
        } catch (InstantiationException | IllegalAccessException | ClassNotFoundException e) {
            throw new IllegalStateException("Unable to instantiate cuba_AuthProvider with class '" + providerClassName + "'");
        }
    }
}
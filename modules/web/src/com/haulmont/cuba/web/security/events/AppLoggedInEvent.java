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

package com.haulmont.cuba.web.security.events;

import com.haulmont.cuba.web.App;
import org.springframework.context.ApplicationEvent;

public class AppLoggedInEvent extends ApplicationEvent {

    public AppLoggedInEvent(App source) {
        super(source);
    }

    @Override
    public App getSource() {
        return (App) super.getSource();
    }

    public App getApp() {
        return (App) super.getSource();
    }
}
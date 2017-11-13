/*
 * Copyright (c) 2008-2017 Haulmont.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0N
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.haulmont.cuba.web.gui.icons;

import com.haulmont.cuba.core.global.AppBeans;
import com.haulmont.cuba.gui.theme.ThemeConstants;
import com.haulmont.cuba.web.App;
import com.vaadin.server.Resource;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

public abstract class AbstractIconProvider implements IconProvider {
    private final Logger log = LoggerFactory.getLogger(AbstractIconProvider.class);

    protected Resource getIconFromTheme(String iconName) {
        String themeIcon = getIconPath(iconName);

        if (StringUtils.isEmpty(themeIcon))
            return null;

        Optional<IconProvider> provider = AppBeans.getAll(IconProvider.class)
                .values().stream()
                .filter(p -> p.canProvide(themeIcon))
                .findAny();

        if (provider.isPresent()) {
            return provider.get().getIconResource(themeIcon);
        }

        log.warn("There is no IconProvider for the given icon: {}", themeIcon);
        return null;
    }

    protected String getIconPath(String iconName) {
        ThemeConstants theme = App.getInstance().getThemeConstants();

        String themeIcon = theme.get("icons." + iconName);

        if (StringUtils.isEmpty(themeIcon)) {
            themeIcon = theme.get("cuba.web." + iconName.replace("/", "."));
        }

        return themeIcon;
    }

    @Override
    public abstract Resource getIconResource(String iconPath);

    @Override
    public abstract boolean canProvide(String iconPath);
}

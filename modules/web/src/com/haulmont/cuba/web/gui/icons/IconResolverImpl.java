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

package com.haulmont.cuba.web.gui.icons;

import com.haulmont.cuba.gui.theme.ThemeConstants;
import com.haulmont.cuba.gui.theme.ThemeConstantsManager;
import com.vaadin.server.Resource;
import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import javax.inject.Inject;
import java.util.List;
import java.util.Optional;

@Component(IconResolver.NAME)
public class IconResolverImpl implements IconResolver {
    private final Logger log = LoggerFactory.getLogger(IconResolverImpl.class);

    @Inject
    protected ThemeConstantsManager themeConstantsManager;

    protected List<IconProvider> iconProviders;

    @Autowired
    protected IconResolverImpl(List<IconProvider> iconProviders) {
        this.iconProviders = iconProviders;
    }

    @Override
    public Resource getIconResource(String iconPath) {
        Resource iconFromTheme = getIconFromTheme(iconPath);
        if (iconFromTheme != null)
            return iconFromTheme;

        return getResource(iconPath);
    }

    protected Resource getResource(String themeIcon) {
        Optional<IconProvider> provider = iconProviders.stream()
                .filter(p -> p.canProvide(themeIcon))
                .findAny();

        if (provider.isPresent()) {
            return provider.get().getIconResource(themeIcon);
        }

        log.warn("There is no IconProvider for the given icon: {}", themeIcon);
        return null;
    }

    protected Resource getIconFromTheme(String iconPath) {
        String themeIcon = getPathFromTheme(processPath(iconPath));

        if (StringUtils.isEmpty(themeIcon))
            return null;

        return getResource(themeIcon);
    }

    protected String getPathFromTheme(String iconName) {
        ThemeConstants theme = themeConstantsManager.getConstants();

        String themeIcon = theme.get("icons." + iconName);

        if (StringUtils.isEmpty(themeIcon)) {
            themeIcon = theme.get("cuba.web." + iconName.replace("/", "."));
        }

        return themeIcon;
    }

    protected String processPath(String iconPath) {
        if (iconPath.contains("/")) {
            iconPath = iconPath.replace("/", ".");
        }

        if (iconPath.contains(":")) {
            iconPath = iconPath.split(":")[1];
        }
        return iconPath;
    }
}

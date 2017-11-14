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

import com.haulmont.cuba.web.toolkit.VersionedThemeResource;
import com.vaadin.server.Resource;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Component;

@Component
public class ThemeIconProvider implements IconProvider {
    protected static final String[] THEME_PREFIXES = {"theme://", "icons/", "app/", "components/"};

    @Override
    public Resource getIconResource(String iconPath) {
        if (StringUtils.isEmpty(iconPath)) {
            throw new IllegalArgumentException("Icon path should not be empty");
        }

        return new VersionedThemeResource(iconPath);
    }

    @Override
    public boolean canProvide(String iconPath) {
        for (String prefix : THEME_PREFIXES) {
            if (iconPath.startsWith(prefix)) {
                return true;
            }
        }

        return false;
    }
}

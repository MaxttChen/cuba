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

package com.haulmont.cuba.gui.icons;

import com.haulmont.bali.util.Preconditions;
import com.haulmont.cuba.core.global.AppBeans;
import com.haulmont.cuba.core.sys.AppContext;
import com.haulmont.cuba.gui.theme.ThemeConstantsManager;
import org.apache.commons.lang.StringUtils;
import org.springframework.stereotype.Component;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

@Component(Icons.NAME)
public class IconsBean implements Icons {

    protected List<Class<? extends IconSet>> iconSets = new LinkedList<>();

    // (icon name -> icon path)
    protected Map<String, String> icons = new ConcurrentHashMap<>();

    protected volatile boolean initialized;

    protected ReadWriteLock lock = new ReentrantReadWriteLock();

    public void init() {
        iconSets.add(CubaIcons.class);

        String iconSetsProp = AppContext.getProperty("cuba.icons.iconSets");
        if (StringUtils.isEmpty(iconSetsProp))
            return;

        String[] iconSets = iconSetsProp.split(", ");
        for (String iconSetFqn : iconSets) {
            try {
                Class<?> iconSetClass = getClass().getClassLoader()
                        .loadClass(iconSetFqn);

                if (!IconSet.class.isAssignableFrom(iconSetClass))
                    continue;

                //noinspection unchecked
                this.iconSets.add((Class<? extends IconSet>) iconSetClass);
            } catch (ClassNotFoundException e) {
                throw new RuntimeException(String.format("Unable to load icon set class: %s", iconSetFqn), e);
            }
        }
    }

    protected void checkInitialized() {
        if (!initialized) {
            lock.readLock().unlock();
            lock.writeLock().lock();
            try {
                if (!initialized) {
                    init();
                    initialized = true;
                }
            } finally {
                lock.readLock().lock();
                lock.writeLock().unlock();
            }
        }
    }

    @Override
    public String get(IconSet icon) {
        Preconditions.checkNotNullArgument(icon);

        return get(icon.name());
    }

    @Override
    public String get(String iconName) {
        lock.readLock().lock();
        try {
            checkInitialized();

            String themeIcon = AppBeans.get(ThemeConstantsManager.class)
                    .getConstants().get(iconName);

            if (StringUtils.isNotEmpty(themeIcon))
                return themeIcon;

            String icon = icons.get(iconName);
            if (StringUtils.isEmpty(icon)) {
                icon = resolveIcon(iconName);

                icons.put(iconName, icon);
            }

            return icon;
        } finally {
            lock.readLock().unlock();
        }
    }

    protected String resolveIcon(String iconName) {
        String iconPath = null;

        for (Class<? extends IconSet> iconSet : iconSets) {
            try {
                Object obj = iconSet.getDeclaredField(iconName).get(null);
                iconPath = ((IconSet) obj).id();
            } catch (IllegalAccessException | NoSuchFieldException ignored) {
            }
        }

        return iconPath;
    }
}
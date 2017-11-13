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

public interface Icons {
    String NAME = "cuba_Icons";

    /**
     * Returns full string path for icon from the given <code>IconSet</code>.
     * <pre>
     * Example:
     * <code>
     * String iconPath = Icons.get(CubaIcons.CREATE);
     * </code></pre>
     *
     * @param icon an icon from the given <code>IconSet</code>
     *
     * @return icon full string path
     */
    String get(IconSet icon);

    /**
     * Returns full string path for icon with the given <code>iconName</code>.
     * <pre>
     * Example:
     * <code>
     * String iconPath = Icons.get("IMPORT");
     * </code></pre>
     * @param iconName icon name
     *
     * @return icon full string path
     */
    String get(String iconName);

    /**
     * Marker interface to mark icon enumerations - icon sets.
     */
    interface IconSet {
        String id();

        String name();
    }
}

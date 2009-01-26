/*
 * Copyright (c) 2008 Haulmont Technology Ltd. All Rights Reserved.
 * Haulmont Technology proprietary and confidential.
 * Use is subject to license terms.

 * Author: Dmitry Abramov
 * Created: 23.12.2008 9:53:35
 * $Id$
 */
package com.haulmont.cuba.gui.components;

import com.haulmont.cuba.gui.WindowManager;

import java.util.Map;
import java.util.ResourceBundle;

public interface IFrame extends OrderedLayout, Component.Container {
    ResourceBundle getResourceBundle();
    void setResourceBundle(ResourceBundle resourceBundle);

    <T extends Window> T openWindow(String descriptor, WindowManager.OpenType openType, Map params);
    <T extends Window> T openWindow(Class aclass, WindowManager.OpenType openType, Map params);

    <T extends Window> T openWindow(String descriptor, WindowManager.OpenType openType);
    <T extends Window> T openWindow(Class aclass, WindowManager.OpenType openType);
}

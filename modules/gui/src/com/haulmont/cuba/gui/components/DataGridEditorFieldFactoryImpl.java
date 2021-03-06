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

package com.haulmont.cuba.gui.components;

import com.haulmont.bali.util.ParamsMap;
import com.haulmont.bali.util.Preconditions;
import com.haulmont.chile.core.model.MetaClass;
import com.haulmont.chile.core.model.MetaProperty;
import com.haulmont.chile.core.model.MetaPropertyPath;
import com.haulmont.chile.core.model.Range;
import com.haulmont.cuba.core.app.dynamicattributes.DynamicAttributesMetaProperty;
import com.haulmont.cuba.core.app.dynamicattributes.DynamicAttributesUtils;
import com.haulmont.cuba.core.app.dynamicattributes.PropertyType;
import com.haulmont.cuba.core.entity.CategoryAttribute;
import com.haulmont.cuba.core.entity.FileDescriptor;
import com.haulmont.cuba.core.entity.annotation.CurrencyValue;
import com.haulmont.cuba.core.global.AppBeans;
import com.haulmont.cuba.core.global.Messages;
import com.haulmont.cuba.gui.ComponentsHelper;
import com.haulmont.cuba.gui.WindowManager;
import com.haulmont.cuba.gui.data.CollectionDatasource;
import com.haulmont.cuba.gui.data.Datasource;
import com.haulmont.cuba.gui.dynamicattributes.DynamicAttributesGuiTools;
import com.haulmont.cuba.gui.xml.layout.ComponentsFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.sql.Time;
import java.util.Collection;
import java.util.Date;
import java.util.UUID;

@org.springframework.stereotype.Component(DataGridEditorFieldFactory.NAME)
public class DataGridEditorFieldFactoryImpl implements DataGridEditorFieldFactory {

    @Inject
    protected Messages messages;

    @Inject
    protected ComponentsFactory componentsFactory;

    @Override
    public Field createField(Datasource datasource, String property) {
        return createFieldComponent(datasource, property);
    }

    protected Field createFieldComponent(Datasource datasource, String property) {
        MetaClass metaClass = datasource.getMetaClass();
        MetaPropertyPath mpp = metaClass.getPropertyPath(property);

        if (mpp == null && DynamicAttributesUtils.isDynamicAttribute(property)) {
            mpp = DynamicAttributesUtils.getMetaPropertyPath(metaClass, property);
        }

        if (mpp != null) {
            Range mppRange = mpp.getRange();
            if (mppRange.isDatatype()) {
                Class type = mppRange.asDatatype().getJavaClass();

                MetaProperty metaProperty = mpp.getMetaProperty();
                if (DynamicAttributesUtils.isDynamicAttribute(metaProperty)) {
                    CategoryAttribute categoryAttribute = DynamicAttributesUtils.getCategoryAttribute(metaProperty);
                    if (categoryAttribute != null && categoryAttribute.getDataType() == PropertyType.ENUMERATION) {
                        return createEnumField(datasource, property);
                    }
                }

                if (type.equals(String.class)) {
                    return createStringField(datasource, property);
                } else if (type.equals(UUID.class)) {
                    return createUuidField(datasource, property);
                } else if (type.equals(Boolean.class)) {
                    return createBooleanField(datasource, property);
                } else if (type.equals(java.sql.Date.class) || type.equals(Date.class)) {
                    return createDateField(datasource, property);
                } else if (type.equals(Time.class)) {
                    return createTimeField(datasource, property);
                } else if (Number.class.isAssignableFrom(type)) {
                    return createNumberField(datasource, property);
                }
            } else if (mppRange.isClass()) {
                MetaProperty metaProperty = mpp.getMetaProperty();
                Class<?> javaType = metaProperty.getJavaType();
                if (FileDescriptor.class.isAssignableFrom(javaType)) {
                    return createFileUploadField(datasource, property);
                }
                if (!Collection.class.isAssignableFrom(javaType)) {
                    return createEntityField(datasource, property, mpp);
                }
            } else if (mppRange.isEnum()) {
                return createEnumField(datasource, property);
            }
        }

        String exceptionMessage;
        if (mpp != null) {
            String name = mpp.getRange().isDatatype()
                    ? mpp.getRange().asDatatype().toString()
                    : mpp.getRange().asClass().getName();
            exceptionMessage = String.format("Can't create field \"%s\" with data type: %s", property, name);
        } else {
            exceptionMessage = String.format("Can't create field \"%s\" with given data type", property);
        }
        throw new UnsupportedOperationException(exceptionMessage);
    }

    protected Field createFileUploadField(Datasource datasource, String property) {
        FileUploadField fileUploadField = (FileUploadField) componentsFactory.createComponent(FileUploadField.NAME);
        fileUploadField.setMode(FileUploadField.FileStoragePutMode.IMMEDIATE);

        fileUploadField.setUploadButtonCaption(null);
        fileUploadField.setUploadButtonDescription(messages.getMainMessage("upload.submit"));
        fileUploadField.setUploadButtonIcon("icons/upload.png");

        fileUploadField.setClearButtonCaption(null);
        fileUploadField.setClearButtonDescription(messages.getMainMessage("upload.clear"));
        fileUploadField.setClearButtonIcon("icons/remove.png");

        fileUploadField.setShowFileName(true);
        fileUploadField.setShowClearButton(true);

        fileUploadField.setDatasource(datasource, property);
        return fileUploadField;
    }

    protected Field createUuidField(Datasource datasource, String property) {
        MaskedField maskedField = componentsFactory.createComponent(MaskedField.class);
        maskedField.setDatasource(datasource, property);
        maskedField.setMask("hhhhhhhh-hhhh-hhhh-hhhh-hhhhhhhhhhhh");
        maskedField.setSendNullRepresentation(false);
        return maskedField;
    }

    protected Field createNumberField(Datasource datasource, String property) {
        Field currencyField = createCurrencyField(datasource, property);
        if (currencyField != null) {
            return currencyField;
        }

        TextField numberField = componentsFactory.createComponent(TextField.class);
        numberField.setDatasource(datasource, property);
        return numberField;
    }

    @Nullable
    protected Field createCurrencyField(Datasource datasource, String property) {
        if (DynamicAttributesUtils.isDynamicAttribute(property))
            return null;

        MetaPropertyPath mpp = datasource.getMetaClass().getPropertyPath(property);
        Preconditions.checkNotNullArgument(mpp, "Could not resolve property path '%s' in '%s'",
                property, datasource.getMetaClass());

        Object currencyAnnotation = mpp.getMetaProperty().getAnnotations().get(CurrencyValue.class.getName());
        if (currencyAnnotation == null) {
            return null;
        }

        CurrencyField currencyField = componentsFactory.createComponent(CurrencyField.class);
        currencyField.setDatasource(datasource, property);

        return currencyField;
    }

    protected Field createBooleanField(Datasource datasource, String property) {
        CheckBox checkBox = componentsFactory.createComponent(CheckBox.class);
        checkBox.setDatasource(datasource, property);
        return checkBox;
    }

    protected Field createStringField(Datasource datasource, String property) {
        TextField textField = componentsFactory.createComponent(TextField.class);
        textField.setDatasource(datasource, property);
        return textField;
    }

    protected Field createDateField(Datasource datasource, String property) {
        DateField dateField = componentsFactory.createComponent(DateField.class);
        dateField.setDatasource(datasource, property);
        return dateField;
    }

    protected Field createTimeField(Datasource datasource, String property) {
        TimeField timeField = componentsFactory.createComponent(TimeField.class);
        timeField.setDatasource(datasource, property);
        return timeField;
    }

    protected Field createEntityField(Datasource datasource, String property, MetaPropertyPath mpp) {
        CollectionDatasource optionsDatasource = null;

        if (DynamicAttributesUtils.isDynamicAttribute(mpp.getMetaProperty())) {
            DynamicAttributesMetaProperty metaProperty = (DynamicAttributesMetaProperty) mpp.getMetaProperty();
            CategoryAttribute attribute = metaProperty.getAttribute();
            if (Boolean.TRUE.equals(attribute.getLookup())) {
                DynamicAttributesGuiTools dynamicAttributesGuiTools = AppBeans.get(DynamicAttributesGuiTools.class);
                optionsDatasource = dynamicAttributesGuiTools.createOptionsDatasourceForLookup(metaProperty.getRange()
                        .asClass(), attribute.getJoinClause(), attribute.getWhereClause());
            }
        }

        PickerField pickerField;
        if (optionsDatasource == null) {
            pickerField = componentsFactory.createComponent(PickerField.class);
            pickerField.setDatasource(datasource, property);
            pickerField.addLookupAction();
            if (DynamicAttributesUtils.isDynamicAttribute(mpp.getMetaProperty())) {
                DynamicAttributesGuiTools dynamicAttributesGuiTools = AppBeans.get(DynamicAttributesGuiTools.class);
                DynamicAttributesMetaProperty dynamicAttributesMetaProperty = (DynamicAttributesMetaProperty) mpp.getMetaProperty();
                dynamicAttributesGuiTools.initEntityPickerField(pickerField, dynamicAttributesMetaProperty.getAttribute());
            }
            PickerField.LookupAction lookupAction =
                    (PickerField.LookupAction) pickerField.getActionNN(PickerField.LookupAction.NAME);
            // Opening lookup screen in another mode will close editor
            lookupAction.setLookupScreenOpenType(WindowManager.OpenType.DIALOG);
            // In case of adding special logic for lookup screen opened from DataGrid editor
            lookupAction.setLookupScreenParams(ParamsMap.of("dataGridEditor", true));
            boolean actionsByMetaAnnotations = ComponentsHelper.createActionsByMetaAnnotations(pickerField);
            if (!actionsByMetaAnnotations) {
                pickerField.addClearAction();
            }
        } else {
            LookupPickerField lookupPickerField = componentsFactory.createComponent(LookupPickerField.class);
            lookupPickerField.setDatasource(datasource, property);
            lookupPickerField.setOptionsDatasource(optionsDatasource);

            pickerField = lookupPickerField;

            ComponentsHelper.createActionsByMetaAnnotations(pickerField);
        }

        return pickerField;
    }

    protected Field createEnumField(Datasource datasource, String property) {
        LookupField lookupField = componentsFactory.createComponent(LookupField.class);
        lookupField.setDatasource(datasource, property);
        return lookupField;
    }
}

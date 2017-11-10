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

package com.haulmont.cuba.web.toolkit.ui;

import com.haulmont.cuba.web.toolkit.ui.client.suggestionfield.CubaSuggestionFieldClientRpc;
import com.haulmont.cuba.web.toolkit.ui.client.suggestionfield.CubaSuggestionFieldServerRpc;
import com.haulmont.cuba.web.toolkit.ui.client.suggestionfield.CubaSuggestionFieldState;
import com.vaadin.event.FieldEvents;
import com.vaadin.server.AbstractErrorMessage;
import com.vaadin.server.CompositeErrorMessage;
import com.vaadin.server.ErrorMessage;
import com.vaadin.server.KeyMapper;
import com.vaadin.ui.AbstractField;
import elemental.json.Json;
import elemental.json.JsonArray;
import elemental.json.JsonObject;
import org.apache.commons.lang.StringUtils;

import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;

public class CubaSuggestionField extends AbstractField<Object> {
    protected static final String SUGGESTION_ID = "id";
    protected static final String SUGGESTION_CAPTION = "caption";

    protected Consumer<String> searchExecutor;
    protected Consumer<String> enterActionHandler;
    protected Consumer<String> arrowDownActionHandler;
    protected Runnable cancelSearchHandler;

    protected KeyMapper keyMapper = new KeyMapper<>();

    protected FieldEvents.FocusAndBlurServerRpcImpl focusBlurRpc;
    protected CubaSuggestionFieldServerRpc serverRpc;

    protected Function<Object, String> textViewConverter;
    protected int suggestionsLimit = 10;

    public CubaSuggestionField() {
        setValidationVisible(false);
        serverRpc = new CubaSuggestionFieldServerRpc() {
            @Override
            public void searchSuggestions(String query) {
                if (searchExecutor != null) {
                    searchExecutor.accept(query);
                }
            }

            @Override
            public void selectSuggestion(String suggestionId) {
                Object suggestion = keyMapper.get(suggestionId);
                setValue(suggestion);

                updateTextPresentation(suggestion);
            }

            @Override
            public void onEnterKeyPressed(String currentSearchString) {
                if (enterActionHandler != null) {
                    enterActionHandler.accept(currentSearchString);
                }
            }

            @Override
            public void onArrowDownKeyPressed(String currentSearchString) {
                if (arrowDownActionHandler != null) {
                    arrowDownActionHandler.accept(currentSearchString);
                }
            }

            @Override
            public void cancelSearch() {
                cancelSearchHandler.run();
            }
        };
        registerRpc(serverRpc);

        focusBlurRpc = new FieldEvents.FocusAndBlurServerRpcImpl(this) {
            private static final long serialVersionUID = -780524775769549747L;

            @Override
            protected void fireEvent(Event event) {
                CubaSuggestionField.this.fireEvent(event);
            }
        };
        registerRpc(focusBlurRpc);
    }

    @Override
    protected void setInternalValue(Object newValue) {
        super.setInternalValue(newValue);

        updateTextPresentation(newValue);
    }

    public void updateTextPresentation(Object value) {
        String stringValue = textViewConverter.apply(value);

        if (!StringUtils.equals(getState(false).text, stringValue)) {
            getState().text = stringValue;
        }
    }

    @Override
    public ErrorMessage getErrorMessage() {
        ErrorMessage superError = super.getErrorMessage();
        if (!isReadOnly() && isRequired() && isEmpty()) {
            ErrorMessage error = AbstractErrorMessage.getErrorMessageForException(
                    new com.vaadin.data.Validator.EmptyValueException(getRequiredError()));
            if (error != null) {
                return new CompositeErrorMessage(superError, error);
            }
        }
        return superError;
    }

    public void setTextViewConverter(Function<?, String> converter) {
        this.textViewConverter = (Function<Object, String>) converter;
    }

    @Override
    public Class<Object> getType() {
        return Object.class;
    }

    public int getAsyncSearchDelayMs() {
        return getState(false).asyncSearchDelayMs;
    }

    public void setAsyncSearchDelayMs(int asyncSearchDelayMs) {
        if (getState(false).asyncSearchDelayMs != asyncSearchDelayMs) {
            getState().asyncSearchDelayMs = asyncSearchDelayMs;
        }
    }

    public void setEnterActionHandler(Consumer<String> enterActionHandler) {
        this.enterActionHandler = enterActionHandler;
    }

    public void setArrowDownActionHandler(Consumer<String> arrowDownActionHandler) {
        this.arrowDownActionHandler = arrowDownActionHandler;
    }

    public int getMinSearchStringLength() {
        return getState(false).minSearchStringLength;
    }

    public void setMinSearchStringLength(int minSearchStringLength) {
        if (getState(false).minSearchStringLength != minSearchStringLength) {
            getState().minSearchStringLength = minSearchStringLength;
        }
    }

    public void setSearchExecutor(Consumer<String> searchExecutor) {
        this.searchExecutor = searchExecutor;
    }

    public void showSuggestions(List<?> suggestions) {
        final JsonArray jsonArray = Json.createArray();
        for (int i = 0; i < suggestions.size() && i < suggestionsLimit; i++) {
            jsonArray.set(i, getJsonObject(suggestions.get(i)));
        }
        getRpcProxy(CubaSuggestionFieldClientRpc.class).showSuggestions(jsonArray);
    }

    public void setCancelSearchHandler(Runnable cancelSearchHandler) {
        this.cancelSearchHandler = cancelSearchHandler;
    }

    @Override
    protected CubaSuggestionFieldState getState() {
        return (CubaSuggestionFieldState) super.getState();
    }

    @Override
    protected CubaSuggestionFieldState getState(boolean markAsDirty) {
        return (CubaSuggestionFieldState) super.getState(markAsDirty);
    }

    private JsonObject getJsonObject(Object suggestion) {
        final JsonObject object = Json.createObject();

        //noinspection unchecked
        object.put(SUGGESTION_ID, Json.create(keyMapper.key(suggestion)));

        String caption = textViewConverter.apply(suggestion);
        object.put(SUGGESTION_CAPTION, Json.create(caption));
        return object;
    }

    public void setSuggestionsLimit(int suggestionsLimit) {
        this.suggestionsLimit = suggestionsLimit;
    }

    public int getSuggestionsLimit() {
        return suggestionsLimit;
    }

    public String getInputPrompt() {
        return getState(false).inputPrompt;
    }

    public void setInputPrompt(String inputPrompt) {
        if (!StringUtils.equals(inputPrompt, getState(false).inputPrompt)) {
            getState().inputPrompt = inputPrompt;
        }
    }
}
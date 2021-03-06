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

package com.haulmont.cuba.core.global;

import com.haulmont.chile.core.datatypes.Datatypes;
import org.springframework.stereotype.Component;

import javax.annotation.Nullable;
import javax.inject.Inject;
import java.math.BigDecimal;
import java.sql.Time;
import java.text.ParseException;
import java.util.Date;
import java.util.TimeZone;

/**
 * Convenience bean for locale-dependent conversion of some widely used data types to and from strings.
 * <p>
 * For locale-independent conversion use {@link com.haulmont.chile.core.datatypes.Datatype} methods directly.
 */
@Component(DatatypeFormatter.NAME)
public class DatatypeFormatter {

    public static final String NAME = "cuba_DatatypeFormatter";

    @Inject
    protected UserSessionSource uss;

    @Inject
    protected TimeZones timeZones;

    /**
     * Format Date (date without time) using {@code dateFormat} string specified in the main message pack.
     * @return string representation or empty string if the value is null
     */
    public String formatDate(@Nullable Date value) {
        return Datatypes.getNN(java.sql.Date.class).format(value, uss.getLocale());
    }

    /**
     * Format Date (time without date) using {@code timeFormat} string specified in the main message pack.
     * @return string representation or empty string if the value is null
     */
    public String formatTime(@Nullable Date value) {
        return Datatypes.getNN(Time.class).format(value, uss.getLocale());
    }

    /**
     * Format Date (date and time) using {@code dateTimeFormat} string specified in the main message pack.
     * <p>Takes into account time zone if it is set for the current user session.</p>
     * @return string representation or empty string if the value is null
     */
    public String formatDateTime(@Nullable Date value) {
        TimeZone tz = uss.getUserSession().getTimeZone();
        if (tz != null)
            value = timeZones.convert(value, TimeZone.getDefault(), tz);

        return Datatypes.getNN(Date.class).format(value, uss.getLocale());
    }

    /**
     * Format Double using {@code doubleFormat} string specified in the main message pack.
     * @return string representation or empty string if the value is null
     */
    public String formatDouble(@Nullable Double value) {
        return Datatypes.getNN(Double.class).format(value, uss.getLocale());
    }

    /**
     * Format BigDecimal using {@code decimalFormat} string specified in the main message pack.
     * @return string representation or empty string if the value is null
     */
    public String formatBigDecimal(@Nullable BigDecimal value) {
        return Datatypes.getNN(BigDecimal.class).format(value, uss.getLocale());
    }

    /**
     * Format Boolean using {@code trueString} and {@code falseString} strings specified in the main message pack.
     * @return string representation or empty string if the value is null
     */
    public String formatBoolean(@Nullable Boolean value) {
        return Datatypes.getNN(Boolean.class).format(value, uss.getLocale());
    }

    /**
     * Format Integer using {@code integerFormat} string specified in the main message pack.
     * @return string representation or empty string if the value is null
     */
    public String formatInteger(@Nullable Integer value) {
        return Datatypes.getNN(Integer.class).format(value, uss.getLocale());
    }

    /**
     * Format Long using {@code integerFormat} string specified in the main message pack.
     * @return string representation or empty string if the value is null
     */
    public String formatLong(@Nullable Long value) {
        return Datatypes.getNN(Long.class).format(value, uss.getLocale());
    }

    /**
     * Parse Date (date without time) using {@code dateFormat} string specified in the main message pack.
     * @return Date value or null if a blank string is provided
     */
    @Nullable
    public Date parseDate(String str) throws ParseException {
        return Datatypes.getNN(java.sql.Date.class).parse(str, uss.getLocale());
    }

    /**
     * Parse Date (time without date) using {@code timeFormat} string specified in the main message pack.
     * @return Date value or null if a blank string is provided
     */
    @Nullable
    public Date parseTime(String str) throws ParseException {
        return Datatypes.getNN(Time.class).parse(str, uss.getLocale());
    }

    /**
     * Parse Date (date and time) using {@code dateTimeFormat} string specified in the main message pack.
     * <p>Takes into account time zone if it is set for the current user session.</p>
     * @return Date value or null if a blank string is provided
     */
    @Nullable
    public Date parseDateTime(String str) throws ParseException {
        Date date = Datatypes.getNN(Date.class).parse(str, uss.getLocale());

        TimeZone tz = uss.getUserSession().getTimeZone();
        if (tz != null)
            date = timeZones.convert(date, tz, TimeZone.getDefault());

        return date;
    }

    /**
     * Parse Double using {@code doubleFormat} string specified in the main message pack.
     * @return Double value or null if a blank string is provided
     */
    @Nullable
    public Double parseDouble(String str) throws ParseException {
        return Datatypes.getNN(Double.class).parse(str, uss.getLocale());
    }

    /**
     * Parse BigDecimal using {@code decimalFormat} string specified in the main message pack.
     * @return BigDecimal value or null if a blank string is provided
     */
    @Nullable
    public BigDecimal parseBigDecimal(String str) throws ParseException {
        return Datatypes.getNN(BigDecimal.class).parse(str, uss.getLocale());
    }

    /**
     * Parse Boolean using {@code trueString} and {@code falseString} strings specified in the main message pack.
     * @return Boolean value or null if a blank string is provided
     */
    @Nullable
    public Boolean parseBoolean(String str) throws ParseException {
        return Datatypes.getNN(Boolean.class).parse(str, uss.getLocale());
    }

    /**
     * Parse Integer using {@code integerFormat} string specified in the main message pack.
     * @return Integer value or null if a blank string is provided
     */
    @Nullable
    public Integer parseInteger(String str) throws ParseException {
        return Datatypes.getNN(Integer.class).parse(str, uss.getLocale());
    }

    /**
     * Parse Long using {@code integerFormat} string specified in the main message pack.
     * @return Long value or null if a blank string is provided
     */
    @Nullable
    public Long parseLong(String str) throws ParseException {
        return Datatypes.getNN(Long.class).parse(str, uss.getLocale());
    }
}
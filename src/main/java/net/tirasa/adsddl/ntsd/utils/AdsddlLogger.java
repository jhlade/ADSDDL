/*
 * Copyright (C) 2015 Tirasa (info@tirasa.net)
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
package net.tirasa.adsddl.ntsd.utils;

import java.util.function.Function;

/**
 * Lightweight, zero-overhead logging facade for ADSDDL.
 * <p>
 * By default, automatically binds to SLF4J if {@code org.slf4j.LoggerFactory} is available on the runtime classpath;
 * otherwise falls back to {@link #NOOP} (silent no-op logger).
 * </p>
 * <p>
 * Applications can completely disable logging at any time via {@code AdsddlLogger.setFactory(null)} or
 * {@code AdsddlLogger.disable()}, switch to {@code java.util.logging} via {@code AdsddlLogger.useJul()},
 * or plug in a custom logger factory via {@link #setFactory(Function)}.
 * </p>
 */
public interface AdsddlLogger {

    /**
     * Silent no-op logger instance with zero runtime overhead.
     */
    AdsddlLogger NOOP = new AdsddlLogger() {
        // uses default no-op methods
    };

    default boolean isTraceEnabled() {
        return false;
    }

    default boolean isDebugEnabled() {
        return false;
    }

    default boolean isInfoEnabled() {
        return false;
    }

    default boolean isWarnEnabled() {
        return false;
    }

    default boolean isErrorEnabled() {
        return false;
    }

    default void trace(final String format, final Object... args) {
        // no-op
    }

    default void debug(final String format, final Object... args) {
        // no-op
    }

    default void info(final String format, final Object... args) {
        // no-op
    }

    default void warn(final String format, final Object... args) {
        // no-op
    }

    default void error(final String msg, final Throwable t) {
        // no-op
    }

    default void error(final String format, final Object... args) {
        // no-op
    }

    /**
     * Obtains a logger for the given class.
     * The returned proxy delegates dynamically to the active factory, so calling {@link #setFactory(Function)}
     * (including {@code setFactory(null)}) takes effect immediately across all classes.
     *
     * @param clazz target class.
     * @return non-null logger instance.
     */
    static AdsddlLogger getLogger(final Class<?> clazz) {
        final String name = clazz == null ? "net.tirasa.adsddl" : clazz.getName();
        return getLogger(name);
    }

    /**
     * Obtains a logger for the given name.
     *
     * @param name logger name.
     * @return non-null logger instance.
     */
    static AdsddlLogger getLogger(final String name) {
        return new AdsddlLoggerBackend.DynamicLogger(name == null ? "net.tirasa.adsddl" : name);
    }

    /**
     * Sets a custom logger factory (or {@code null} to disable all logging and use {@link #NOOP}).
     *
     * @param factory function mapping logger name to an {@link AdsddlLogger}, or {@code null} for no-op.
     */
    static void setFactory(final Function<String, AdsddlLogger> factory) {
        AdsddlLoggerBackend.setFactory(factory);
    }

    /**
     * Gets the currently active logger factory.
     *
     * @return current logger factory (never {@code null}).
     */
    static Function<String, AdsddlLogger> getFactory() {
        return AdsddlLoggerBackend.getFactory();
    }

    /**
     * Disables all logging (equivalent to {@code setFactory(null)}).
     */
    static void disable() {
        AdsddlLoggerBackend.setFactory(null);
    }

    /**
     * Enables {@code java.util.logging} (JUL) as the logging backend.
     */
    static void useJul() {
        AdsddlLoggerBackend.setFactory(AdsddlLoggerBackend::createJulLogger);
    }

    /**
     * Restores the default auto-detected backend (SLF4J if present on classpath, otherwise {@link #NOOP}).
     */
    static void resetDefault() {
        AdsddlLoggerBackend.setFactory(AdsddlLoggerBackend.detectDefaultFactory());
    }

    /**
     * Formats an SLF4J-style message pattern (replacing {@code {}} placeholders with arguments).
     *
     * @param pattern message pattern with {@code {}} placeholders.
     * @param args arguments.
     * @return formatted string.
     */
    static String format(final String pattern, final Object... args) {
        return AdsddlLoggerBackend.format(pattern, args);
    }
}

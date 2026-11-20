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

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.logging.Level;

/**
 * Internal backend support for {@link AdsddlLogger}.
 */
final class AdsddlLoggerBackend {

    private static final Function<String, AdsddlLogger> NOOP_FACTORY = name -> AdsddlLogger.NOOP;

    private static final AtomicInteger EPOCH = new AtomicInteger(1);

    private static volatile Function<String, AdsddlLogger> activeFactory = detectDefaultFactory();

    private AdsddlLoggerBackend() {
    }

    static Function<String, AdsddlLogger> getFactory() {
        return activeFactory;
    }

    static void setFactory(final Function<String, AdsddlLogger> factory) {
        activeFactory = factory == null ? NOOP_FACTORY : factory;
        EPOCH.incrementAndGet();
    }

    static Function<String, AdsddlLogger> detectDefaultFactory() {
        try {
            Class.forName("org.slf4j.LoggerFactory", false, AdsddlLoggerBackend.class.getClassLoader());
            return Slf4jBridge::create;
        } catch (Throwable ignored) {
            return NOOP_FACTORY;
        }
    }

    static AdsddlLogger createJulLogger(final String name) {
        final java.util.logging.Logger jul = java.util.logging.Logger.getLogger(name);
        return new AdsddlLogger() {

            @Override
            public boolean isTraceEnabled() {
                return jul.isLoggable(Level.FINEST);
            }

            @Override
            public boolean isDebugEnabled() {
                return jul.isLoggable(Level.FINE);
            }

            @Override
            public boolean isInfoEnabled() {
                return jul.isLoggable(Level.INFO);
            }

            @Override
            public boolean isWarnEnabled() {
                return jul.isLoggable(Level.WARNING);
            }

            @Override
            public boolean isErrorEnabled() {
                return jul.isLoggable(Level.SEVERE);
            }

            @Override
            public void trace(final String format, final Object... args) {
                if (jul.isLoggable(Level.FINEST)) {
                    logJul(Level.FINEST, format, args);
                }
            }

            @Override
            public void debug(final String format, final Object... args) {
                if (jul.isLoggable(Level.FINE)) {
                    logJul(Level.FINE, format, args);
                }
            }

            @Override
            public void info(final String format, final Object... args) {
                if (jul.isLoggable(Level.INFO)) {
                    logJul(Level.INFO, format, args);
                }
            }

            @Override
            public void warn(final String format, final Object... args) {
                if (jul.isLoggable(Level.WARNING)) {
                    logJul(Level.WARNING, format, args);
                }
            }

            @Override
            public void error(final String msg, final Throwable t) {
                if (jul.isLoggable(Level.SEVERE)) {
                    jul.log(Level.SEVERE, msg, t);
                }
            }

            @Override
            public void error(final String format, final Object... args) {
                if (jul.isLoggable(Level.SEVERE)) {
                    logJul(Level.SEVERE, format, args);
                }
            }

            private void logJul(final Level level, final String pattern, final Object... args) {
                Throwable t = null;
                Object[] effectiveArgs = args;
                if (args != null && args.length > 0 && args[args.length - 1] instanceof Throwable) {
                    t = (Throwable) args[args.length - 1];
                }
                jul.log(level, format(pattern, effectiveArgs), t);
            }
        };
    }

    static String format(final String pattern, final Object... args) {
        if (pattern == null || args == null || args.length == 0) {
            return pattern;
        }
        final StringBuilder sb = new StringBuilder(pattern.length() + 32);
        int cursor = 0;
        int argIndex = 0;
        while (argIndex < args.length) {
            final int placeholder = pattern.indexOf("{}", cursor);
            if (placeholder < 0) {
                break;
            }
            sb.append(pattern, cursor, placeholder);
            sb.append(args[argIndex++]);
            cursor = placeholder + 2;
        }
        sb.append(pattern, cursor, pattern.length());
        return sb.toString();
    }

    /**
     * Isolated SLF4J bridge class loaded only when {@code org.slf4j.LoggerFactory} is present on the classpath.
     */
    private static final class Slf4jBridge {

        private Slf4jBridge() {
        }

        static AdsddlLogger create(final String name) {
            final org.slf4j.Logger slf4j = org.slf4j.LoggerFactory.getLogger(name);
            return new AdsddlLogger() {

                @Override
                public boolean isTraceEnabled() {
                    return slf4j.isTraceEnabled();
                }

                @Override
                public boolean isDebugEnabled() {
                    return slf4j.isDebugEnabled();
                }

                @Override
                public boolean isInfoEnabled() {
                    return slf4j.isInfoEnabled();
                }

                @Override
                public boolean isWarnEnabled() {
                    return slf4j.isWarnEnabled();
                }

                @Override
                public boolean isErrorEnabled() {
                    return slf4j.isErrorEnabled();
                }

                @Override
                public void trace(final String format, final Object... args) {
                    slf4j.trace(format, args);
                }

                @Override
                public void debug(final String format, final Object... args) {
                    slf4j.debug(format, args);
                }

                @Override
                public void info(final String format, final Object... args) {
                    slf4j.info(format, args);
                }

                @Override
                public void warn(final String format, final Object... args) {
                    slf4j.warn(format, args);
                }

                @Override
                public void error(final String msg, final Throwable t) {
                    slf4j.error(msg, t);
                }

                @Override
                public void error(final String format, final Object... args) {
                    slf4j.error(format, args);
                }
            };
        }
    }

    /**
     * Epoch-cached dynamic delegate so static {@code LOG} fields reflect {@link AdsddlLogger#setFactory(Function)}
     * changes immediately without re-creating delegates on every log call.
     */
    static final class DynamicLogger implements AdsddlLogger {

        private final String name;

        private volatile int cachedEpoch = -1;

        private volatile AdsddlLogger cachedDelegate = AdsddlLogger.NOOP;

        DynamicLogger(final String name) {
            this.name = name;
        }

        private AdsddlLogger delegate() {
            final int currentEpoch = EPOCH.get();
            if (cachedEpoch != currentEpoch) {
                final AdsddlLogger created = activeFactory.apply(name);
                cachedDelegate = created == null ? AdsddlLogger.NOOP : created;
                cachedEpoch = currentEpoch;
            }
            return cachedDelegate;
        }

        @Override
        public boolean isTraceEnabled() {
            return delegate().isTraceEnabled();
        }

        @Override
        public boolean isDebugEnabled() {
            return delegate().isDebugEnabled();
        }

        @Override
        public boolean isInfoEnabled() {
            return delegate().isInfoEnabled();
        }

        @Override
        public boolean isWarnEnabled() {
            return delegate().isWarnEnabled();
        }

        @Override
        public boolean isErrorEnabled() {
            return delegate().isErrorEnabled();
        }

        @Override
        public void trace(final String format, final Object... args) {
            delegate().trace(format, args);
        }

        @Override
        public void debug(final String format, final Object... args) {
            delegate().debug(format, args);
        }

        @Override
        public void info(final String format, final Object... args) {
            delegate().info(format, args);
        }

        @Override
        public void warn(final String format, final Object... args) {
            delegate().warn(format, args);
        }

        @Override
        public void error(final String msg, final Throwable t) {
            delegate().error(msg, t);
        }

        @Override
        public void error(final String format, final Object... args) {
            delegate().error(format, args);
        }
    }
}

package de.fhhannover.inform.trust.ironvas;

/*
 * #%L
 * ====================================================
 *   _____                _     ____  _____ _   _ _   _
 *  |_   _|_ __ _   _ ___| |_  / __ \|  ___| | | | | | |
 *    | | | '__| | | / __| __|/ / _` | |_  | |_| | |_| |
 *    | | | |  | |_| \__ \ |_| | (_| |  _| |  _  |  _  |
 *    |_| |_|   \__,_|___/\__|\ \__,_|_|   |_| |_|_| |_|
 *                             \____/
 * 
 * =====================================================
 * 
 * Fachhochschule Hannover 
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.inform.fh-hannover.de/
 * 
 * This file is part of ironvas, version 0.1.1, implemented by the Trust@FHH 
 * research group at the Fachhochschule Hannover.
 * 
 * ironvas is a *highly experimental* integration of Open Vulnerability Assessment 
 * System (OpenVAS) into a MAP-Infrastructure. The integration aims to share security 
 * related informations (vulnerabilities detected by OpenVAS) with other network 
 * components in the TNC architecture via IF-MAP.
 * %%
 * Copyright (C) 2011 - 2013 Trust@FHH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.logging.Logger;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

/**
 * A {@link ScriptableFilter} is a {@link VulnerabilityFilter} which uses
 * a scripting engine and a external script to make a filter decision for
 * {@link Vulnerability} objects.
 *
 * @author Ralf Steuerwald
 *
 */
public class ScriptableFilter implements VulnerabilityFilter {

    private static final Logger logger = Logger
            .getLogger(ScriptableFilter.class.getName());

    private static final String SCRIPT = "/filter.js";
    private static final String FUNCTION = "filter";

    private static final boolean DEFAULT_RESULT = true;

    private ScriptEngineManager manager;
    private ScriptEngine engine;

    /**
     * Creates a new {@link ScriptableFilter} with a JavaScript engine and
     * uses a script named <tt>filter.js</tt> at the top of the classpath.
     *
     * @throws FilterInitializationException if something goes wrong while
     *                                        setting up the filter
     */
    public ScriptableFilter() {
        manager = new ScriptEngineManager();
        engine = manager.getEngineByName("JavaScript");

        InputStream inStream = getClass().getResourceAsStream(SCRIPT);
        if (inStream == null) {
            throw new FilterInitializationException();
        }
        InputStreamReader in = new InputStreamReader(getClass()
                .getResourceAsStream(SCRIPT));

        try {
            engine.eval(in);
        } catch (ScriptException e) {
            logger.warning("could not evaluate '" + SCRIPT + "'");
        }
    }

    public boolean filter(Vulnerability v) {
        try {
            Invocable inv = (Invocable) engine;
            Boolean result = (Boolean) inv.invokeFunction(FUNCTION, v);
            return result;
        } catch (NoSuchMethodException e) {
            logger.warning("could not invoke '" + FUNCTION + "'");
            return DEFAULT_RESULT;
        } catch (ScriptException e) {
            logger.warning(e.getMessage());
            return DEFAULT_RESULT;
        } catch (ClassCastException e) {
            logger.warning(e.getMessage());
            return DEFAULT_RESULT;
        }
    }
}

class FilterInitializationException extends RuntimeException {}

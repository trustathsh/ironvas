/*
 * #%L
 * =====================================================
 *   _____                _     ____  _   _       _   _
 *  |_   _|_ __ _   _ ___| |_  / __ \| | | | ___ | | | |
 *    | | | '__| | | / __| __|/ / _` | |_| |/ __|| |_| |
 *    | | | |  | |_| \__ \ |_| | (_| |  _  |\__ \|  _  |
 *    |_| |_|   \__,_|___/\__|\ \__,_|_| |_||___/|_| |_|
 *                             \____/
 * 
 * =====================================================
 * 
 * Hochschule Hannover
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.f4.hs-hannover.de
 * 
 * This file is part of ironvas, version 0.1.5, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2011 - 2015 Trust@HsH
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
package de.hshannover.f4.trust.ironvas;

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

    private static final Logger LOGGER = Logger
            .getLogger(ScriptableFilter.class.getName());

    private static final String SCRIPT = "/filter.js";
    private static final String FUNCTION = "filter";

    private static final boolean DEFAULT_RESULT = true;

    private ScriptEngineManager mManager;
    private ScriptEngine mEngine;

    /**
     * Creates a new {@link ScriptableFilter} with a JavaScript engine and
     * uses a script named <tt>filter.js</tt> at the top of the classpath.
     */
    public ScriptableFilter() {
        mManager = new ScriptEngineManager();
        mEngine = mManager.getEngineByName("JavaScript");

        InputStream inStream = getClass().getResourceAsStream(SCRIPT);
        if (inStream == null) {
            throw new FilterInitializationException();
        }
        InputStreamReader in = new InputStreamReader(getClass()
                .getResourceAsStream(SCRIPT));

        try {
            mEngine.eval(in);
        } catch (ScriptException e) {
            LOGGER.warning("could not evaluate '" + SCRIPT + "'");
        }
    }

    @Override
	public boolean filter(Vulnerability v) {
        try {
            Invocable inv = (Invocable) mEngine;
            Boolean result = (Boolean) inv.invokeFunction(FUNCTION, v);
            return result;
        } catch (NoSuchMethodException e) {
            LOGGER.warning("could not invoke '" + FUNCTION + "'");
            return DEFAULT_RESULT;
        } catch (ScriptException e) {
            LOGGER.warning(e.getMessage());
            return DEFAULT_RESULT;
        } catch (ClassCastException e) {
            LOGGER.warning(e.getMessage());
            return DEFAULT_RESULT;
        }
    }
}

class FilterInitializationException extends RuntimeException {}

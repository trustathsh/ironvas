package de.fhhannover.inform.trust.ironvas;

import java.io.InputStreamReader;
import java.util.logging.Logger;

import javax.script.Invocable;
import javax.script.ScriptEngine;
import javax.script.ScriptEngineManager;
import javax.script.ScriptException;

public class ScriptableFilter implements VulnerabilityFilter {

    private static final Logger logger = Logger
            .getLogger(ScriptableFilter.class.getName());

    private static final String SCRIPT = "/filter.js";
    private static final String FUNCTION = "filter";

    private static final boolean DEFAULT_RESULT = true;

    private ScriptEngineManager manager;
    private ScriptEngine engine;

    public ScriptableFilter() {
        manager = new ScriptEngineManager();
        engine = manager.getEngineByName("JavaScript");

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

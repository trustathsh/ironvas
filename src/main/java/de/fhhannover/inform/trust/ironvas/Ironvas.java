/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas
 * File:    Ironvas.java
 *
 * Copyright (C) 2011-2012 Hochschule Hannover
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.fhhannover.inform.trust.ironvas;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import de.fhhannover.inform.trust.ifmapj.IfmapJHelper;
import de.fhhannover.inform.trust.ifmapj.channel.SSRC;
import de.fhhannover.inform.trust.ifmapj.exception.InitializationException;
import de.fhhannover.inform.trust.ironvas.converter.Converter;
import de.fhhannover.inform.trust.ironvas.ifmap.Keepalive;
import de.fhhannover.inform.trust.ironvas.ifmap.ThreadSafeSsrc;
import de.fhhannover.inform.trust.ironvas.omp.OmpConnection;
import de.fhhannover.inform.trust.ironvas.omp.VulnerabilityFetcher;
import de.fhhannover.inform.trust.ironvas.subscriber.Subscriber;

/**
 * Ironvas is an IF-MAP client which integrates OpenVAS into an IF-MAP
 * environment.
 *
 * @author Ralf Steuerwald
 *
 */
public class Ironvas implements Runnable {

    private static final Logger logger = Logger.getLogger(Ironvas.class
            .getName());
    private static final String LOGGING_CONFIG_FILE = "/logging.properties";

    private SSRC ssrc;
    private OmpConnection omp;
    private Keepalive ssrcKeepalive;

    private Converter converter;
    private VulnerabilityHandler handler;
    private VulnerabilityFetcher fetcher;

    private Subscriber subscriber;

    private Thread handlerThread;
    private Thread fetcherThread;
    private Thread subscriberThread;
    private Thread ssrcKeepaliveThread;

    private ShutdownHook shutdownHook;

    /**
     * Initializes all ironvas components based on the parameter in
     * {@link Configuration}, therefore the {@link Configuration} must be loaded
     * before calling this constructor.
     */
    public Ironvas() {
        ssrc = initIfmap();
        omp = initOmp();
        ssrcKeepalive = new Keepalive(ssrc, Configuration.ifmapKeepalive());

        converter = createConverter(ssrc, omp);
        handler = new VulnerabilityHandler(ssrc, converter);

        VulnerabilityFilter vulnerabilityFilter = null;
        try {
            vulnerabilityFilter = new ScriptableFilter();
            fetcher = new VulnerabilityFetcher(handler, omp,
                    Configuration.publishInterval(), vulnerabilityFilter);
        } catch (FilterInitializationException e) {
            logger.warning("could not load filter.js, falling back to no " +
                    "filtering");
            fetcher = new VulnerabilityFetcher(handler, omp,
                        Configuration.publishInterval());
        }

        subscriber = new Subscriber(omp, ssrc, Configuration.subscriberPdp(),
                Configuration.subscriberNamePrefix(),
                Configuration.subscriberConfig());

        // TODO: introduce supervisor thread to control the different sub-threads (clean exit, error handling, ...)
        handlerThread = new Thread(handler, "handler-thread");
        fetcherThread = new Thread(fetcher, "fetcher-thread");
        subscriberThread = new Thread(subscriber, "subscriber-thread");
        ssrcKeepaliveThread = new Thread(ssrcKeepalive, "ssrc-keepalive-thread");

        shutdownHook = new ShutdownHook();
        shutdownHook.add(handlerThread);
        shutdownHook.add(fetcherThread);
        shutdownHook.add(subscriberThread);
        shutdownHook.add(ssrcKeepaliveThread);
        Runtime.getRuntime().addShutdownHook(new Thread(shutdownHook));
    }

    @Override
    public void run() {
        if (!Configuration.publisherEnable()
                && !Configuration.subscriberEnable()) {
            logger.warning("nothing to do, shutting down ...");
            System.exit(0);
        }

        try {
            ssrc.newSession();
            ssrc.purgePublisher();
        } catch (Exception e) {
            System.err.println("could not connect to ifmap server: " + e);
            System.exit(1);
        }

        ssrcKeepaliveThread.start();

        if (Configuration.publisherEnable()) {
            logger.info("activate publisher ...");
            handlerThread.start();
            fetcherThread.start();
        }
        if (Configuration.subscriberEnable()) {
            logger.info("activate subscriber ...");
            subscriberThread.start();
        }
    }

    public static void main(String[] args) {
        setupLogging();
        Configuration.init();

        // TODO command line parser
        // overwrite configuration with command line arguments

        Ironvas ironvas = new Ironvas();
        ironvas.run(); // execute ironvas in the main thread

    }

    /**
     * Creates a {@link Converter} instance with the given configuration
     * parameters.
     *
     * @param publisherId
     * @param openvasId
     * @param filterUpdate
     * @param filterNotify
     * @return
     */
    public static Converter createConverter(SSRC ssrc, OmpConnection omp) {
        Context context = new Context(ssrc, "openvas@" + omp.host());

        Converter converter = null;
        String className = Configuration.getConverterName();

        logger.info("try to load '" + className + "'");
        try {
            Class<?> clazz = Class.forName(className);
            Class<?>[] interfaces = clazz.getInterfaces();

            boolean implementsConverter = false;
            for (Class<?> i : interfaces) {
                if (i.equals(Converter.class)) {
                    implementsConverter = true;
                }
            }
            if (!implementsConverter) {
                throw new RuntimeException("'" + className + "' does not "
                        + "implement the Converter interface");
            }
            converter = (Converter) clazz.newInstance();

        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        } catch (InstantiationException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        }

        converter.setContext(context);
        return converter;
    }

    /**
     * Creates a {@link SSRC} instance with the given configuration parameters.
     *
     * @param authMethod
     * @param basicUrl
     * @param certUrl
     * @param user
     * @param pass
     * @param keypath
     * @param keypass
     * @return
     */
    public static SSRC initIfmap(String authMethod, String basicUrl,
            String certUrl, String user, String pass, String keypath,
            String keypass) {
        SSRC ifmap = null;
        TrustManager[] tm = null;
        KeyManager[] km = null;

        try {
            tm = IfmapJHelper.getTrustManagers(
                    Ironvas.class.getResourceAsStream(keypath), keypass);
            km = IfmapJHelper.getKeyManagers(
                    Ironvas.class.getResourceAsStream(keypath), keypass);
        } catch (InitializationException e1) {
            e1.printStackTrace();
            System.exit(1);
        }

        try {
            if (authMethod.equals("basic")) {
                ifmap = new ThreadSafeSsrc(basicUrl, user, pass, tm);
            } else if (authMethod.equals("cert")) {
                ifmap = new ThreadSafeSsrc(certUrl, km, tm);
            } else {
                throw new IllegalArgumentException(
                        "unknown authentication method '" + authMethod + "'");
            }
        } catch (InitializationException e) {
            e.printStackTrace();
            System.exit(1);
        }
        return ifmap;
    }

    /**
     * Creates a {@link SSRC} instance based on the values in
     * {@link Configuration}.
     *
     * @return
     */
    public static SSRC initIfmap() {
        return initIfmap(Configuration.ifmapAuthMethod(),
                Configuration.ifmapUrlBasic(), Configuration.ifmapUrlCert(),
                Configuration.ifmapBasicUser(),
                Configuration.ifmapBasicPassword(),
                Configuration.keyStorePath(), Configuration.keyStorePassword());
    }

    /**
     * Creates an {@link omp.OmpConnection} instance with the given
     * configuration parameters.
     *
     * @param ip
     * @param port
     * @param user
     * @param pass
     * @param keypath
     * @param keypass
     * @return
     */
    public static OmpConnection initOmp(String ip, int port, String user,
            String pass, String keypath, String keypass) {
        OmpConnection omp = new OmpConnection(ip, port, user, pass, keypath,
                keypass);
        return omp;
    }

    /**
     * Creates an {@link omp.OmpConnection} instane based on the values in
     * {@link Configuration}.
     *
     * @return
     */
    public static OmpConnection initOmp() {
        return initOmp(Configuration.openvasIP(), Configuration.openvasPort(),
                Configuration.openvasUser(), Configuration.openvasPassword(),
                Configuration.keyStorePath(), Configuration.keyStorePassword());
    }

    public static void setupLogging() {
        InputStream in = Ironvas.class.getResourceAsStream(LOGGING_CONFIG_FILE);

        try {
            LogManager.getLogManager().readConfiguration(in);
        } catch (Exception e) {
            System.err.println("could not read " + LOGGING_CONFIG_FILE
                    + ", using defaults");
            Handler handler = new ConsoleHandler();
            Logger.getLogger("").addHandler(handler);
            Logger.getLogger("").setLevel(Level.INFO);
        } finally {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}

class ThreadList extends ArrayList<Thread> {
}

class ShutdownHook extends ThreadList implements Runnable {

    @Override
    public void run() {
        for (Thread t : this) {
            t.interrupt();
        }
    }
}

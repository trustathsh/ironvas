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
 * This file is part of ironvas, version 0.1.3, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2011 - 2014 Trust@HsH
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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * This class loads the configuration file from the file system and provides a
 * set of constants and a getter method to access these values.
 *
 * @author Ralf Steuerwald
 *
 */
public final class Configuration {

    private static final Logger LOGGER = Logger.getLogger(Configuration.class
            .getName());

    /**
     * The path to the configuration file.
     */
    private static final String CONFIG_FILE = "/configuration.properties";

    private static Properties properties;

    // begin configuration parameter -------------------------------------------

    private static final String PUBLISHER_ENABLE = "ironvas.publisher.enable";
    private static final String SUBSCRIBER_ENABLE = "ironvas.subscriber.enable";

    private static final String IFMAP_AUTH_METHOD = "ifmap.server.auth.method";
    private static final String IFMAP_URL_BASIC = "ifmap.server.url.basic";
    private static final String IFMAP_URL_CERT = "ifmap.server.url.cert";
    private static final String IFMAP_BASIC_USER = "ifmap.server.auth.basic.user";
    private static final String IFMAP_BASIC_PASSWORD = "ifmap.server.auth.basic.password";

    private static final String KEYSTORE_PATH = "keystore.path";
    private static final String KEYSTORE_PASSWORD = "keystore.password";

    private static final String OPENVAS_IP = "openvas.server.ip";
    private static final String OPENVAS_PORT = "openvas.server.omp.port";
    private static final String OPENVAS_USER = "openvas.server.omp.user";
    private static final String OPENVAS_PASSWORD = "openvas.server.omp.password";

    private static final String PUBLISH_INTERVAL = "ironvas.omp.interval";
    private static final String IFMAP_KEEPALIVE = "ironvas.ifmap.interval";

    // publisher
    private static final String CONVERTER_NAME = "ironvas.publish.converter";

    // subscriber
    private static final String SUBSCRIBER_PDP = "ironvas.subscriber.pdp";
    private static final String SUBSCRIBER_NAME_PREFIX = "ironvas.subscriber.namePrefix";
    private static final String SUBSCRIBER_CONFIG = "ironvas.subscriber.config";

    // end configuration parameter ---------------------------------------------

    private Configuration() { }

    /**
     * Loads the configuration file. Every time this method is called the file
     * is read again.
     */
    public static void init() {
        LOGGER.info("reading " + CONFIG_FILE + " ...");

        properties = new Properties();
        InputStream in = Configuration.class.getResourceAsStream(CONFIG_FILE);
        try {
            properties.load(in);
        } catch (FileNotFoundException e) {
            LOGGER.severe("could not find " + CONFIG_FILE);
            throw new RuntimeException(e.getMessage());
        } catch (IOException e) {
            LOGGER.severe("error while reading " + CONFIG_FILE);
            throw new RuntimeException(e.getMessage());
        } finally {
            try {
                in.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * Returns the value assigned to the given key. If the configuration has not
     * been loaded jet this method loads it.
     *
     * @param key
     * @return the value assigned to key or null if the is none
     */
    private static String get(String key) {
        if (properties == null) {
            init();
        }
        return properties.getProperty(key);
    }

    public static boolean publisherEnable() {
        return get(PUBLISHER_ENABLE).equals("true");
    }

    public static boolean subscriberEnable() {
        return get(SUBSCRIBER_ENABLE).equals("true");
    }

    public static String ifmapAuthMethod() {
        return get(IFMAP_AUTH_METHOD);
    }

    public static String ifmapUrlBasic() {
        return get(IFMAP_URL_BASIC);
    }

    public static String ifmapUrlCert() {
        return get(IFMAP_URL_CERT);
    }

    public static String ifmapBasicUser() {
        return get(IFMAP_BASIC_USER);
    }

    public static String ifmapBasicPassword() {
        return get(IFMAP_BASIC_PASSWORD);
    }

    public static String keyStorePath() {
        return get(KEYSTORE_PATH);
    }

    public static String keyStorePassword() {
        return get(KEYSTORE_PASSWORD);
    }

    public static String openvasIp() {
        return get(OPENVAS_IP);
    }

    public static int openvasPort() {
        return Integer.parseInt(get(OPENVAS_PORT));
    }

    public static String openvasUser() {
        return get(OPENVAS_USER);
    }

    public static String openvasPassword() {
        return get(OPENVAS_PASSWORD);
    }

    public static int publishInterval() {
        return Integer.parseInt(get(PUBLISH_INTERVAL));
    }

    public static int ifmapKeepalive() {
        return Integer.parseInt(get(IFMAP_KEEPALIVE));
    }

    public static String subscriberPdp() {
        return get(SUBSCRIBER_PDP);
    }

    public static String subscriberNamePrefix() {
        return get(SUBSCRIBER_NAME_PREFIX);
    }

    public static String subscriberConfig() {
        return get(SUBSCRIBER_CONFIG);
    }

    public static String getConverterName() {
        return get(CONVERTER_NAME);
    }

}

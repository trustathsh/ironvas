/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas
 * File:    Configuration.java
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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * This class loads the configuration file from the file system and provides
 * a set of constants and a getter method to access these values.
 * 
 * @author Ralf Steuerwald
 *
 */
public class Configuration {
	
	private static final Logger logger =
			Logger.getLogger(Configuration.class.getName());
	
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
	private static final String IFMAP_KEEPALIVE  = "ironvas.ifmap.interval";
	
	// publisher
	private static final String UPDATE_FILTER    = "ironvas.publish.update";
	private static final String NOTIFY_FILTER    = "ironvas.publish.notify";
	
	// subscriber
	private static final String SUBSCRIBER_PDP = "ironvas.subscriber.pdp";
	private static final String SUBSCRIBER_NAME_PREFIX = "ironvas.subscriber.namePrefix";
	private static final String SUBSCRIBER_CONFIG = "ironvas.subscriber.config";
	
	// end configuration parameter ---------------------------------------------
	

	/**
	 * Loads the configuration file. Every time this method is called the
	 * file is read again.
	 */
	public static void init() {
		logger.info("reading " + CONFIG_FILE + " ...");
		
		properties = new Properties();
		InputStream in = Configuration.class.getResourceAsStream(CONFIG_FILE);
		try {
			properties.load(in);
		} catch (FileNotFoundException e) {
			logger.severe("could not find " + CONFIG_FILE);
			throw new RuntimeException(e.getMessage());
		} catch (IOException e) {
			logger.severe("error while reading " + CONFIG_FILE);
			throw new RuntimeException(e.getMessage());
		}
		finally {
			try {
				in.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	/**
	 * Returns the value assigned to the given key. If the configuration has
	 * not been loaded jet this method loads it.
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
	
	public static String publisherEnable() {
		return get(PUBLISHER_ENABLE);
	}
	
	public static String subscriberEnable() {
		return get(SUBSCRIBER_ENABLE);
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
	
	public static String openvasIP() {
		return get(OPENVAS_IP);
	}

	public static String openvasPort() {
		return get(OPENVAS_PORT);
	}

	public static String openvasUser() {
		return get(OPENVAS_USER);
	}
	
	public static String openvasPassword() {
		return get(OPENVAS_PASSWORD);
	}

	public static String publishInterval() {
		return get(PUBLISH_INTERVAL);
	}

	public static String ifmapKeepalive() {
		return get(IFMAP_KEEPALIVE);
	}

	public static String updateFilter() {
		return get(UPDATE_FILTER);
	}
	
	public static String notifyFilter() {
		return get(NOTIFY_FILTER);
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

}

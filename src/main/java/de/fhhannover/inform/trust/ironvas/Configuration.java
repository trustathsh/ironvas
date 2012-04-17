/*
 * Project: ironvas
 * Package: main.java.de.fhhannover.inform.trust.ironvas
 * File:    Configuration.java
 *
 * Copyright (C) 2011-2012 Fachhochschule Hannover
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

	public static final String OPENVAS_IP =
			"openvas.server.ip";
	public static final String OPENVAS_OMP_PORT =
			"openvas.server.omp.port";
	public static final String OPENVAS_OMP_USER =
			"openvas.server.omp.user";
	public static final String OPENVAS_OMP_PASSWORD =
			"openvas.server.omp.password";
	
	public static final String MAPS_URL_BASIC_AUTH = "ifmap.server.url.basic";
	public static final String MAPS_URL_CERT_AUTH = "ifmap.server.url.cert";

	public static final String MAPS_AUTH_BASIC_USER =
			"ifmap.server.auth.basic.user";
	public static final String MAPS_AUTH_BASIC_PASSWORD =
			"ifmap.server.auth.basic.password";
	
	public static final String KEYSTORE_PATH = "keystore.path";
	public static final String KEYSTORE_PASSWORD = "keystore.password";
	
	public static final String OMP_INTERVAL = "ironvas.omp.interval";
	public static final String IFMAP_INTERVAL = "ironvas.ifmap.interval";
	
	private static Properties properties;

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
	public static String get(String key) {
		if (properties == null) {
			init();
		}
		return properties.getProperty(key);
	}

}

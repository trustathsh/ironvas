/*
 * Project: ironvas
 * Package: main.java.de.fhhannover.inform.trust.ironvas
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
import java.util.List;
import java.util.Map;
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
import de.fhhannover.inform.trust.ironvas.converter.FilterEventUpdateConverter;
import de.fhhannover.inform.trust.ironvas.converter.FilterParser;
import de.fhhannover.inform.trust.ironvas.converter.FullEventUpdateConverter;
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
public class Ironvas {
	
	private static final Logger logger =
			Logger.getLogger(Ironvas.class.getName());
	private static final String LOGGING_CONFIG_FILE = "/logging.properties";
	
	public static void main(String[] args) {
		setupLogging();
		Configuration.init();
		
		// TODO command line parser
		// overwrite configuration with command line arguments

		
		// begin initialization ------------------------------------------------
		
		
		if (Configuration.publisherEnable().equals("false") &&
				Configuration.subscriberEnable().equals("false")) {
			logger.warning("nothing to do, shutting down ...");
		}
		else {
			ShutdownHook hook = new ShutdownHook();
			Runtime.getRuntime().addShutdownHook(new Thread(hook));
			ThreadInterruptionWatcher watcher = new ThreadInterruptionWatcher();

			SSRC ssrc = initIfmap();

			try {
				ssrc.newSession();
				ssrc.purgePublisher();
			} catch (Exception e) {
				System.err.println("could not connect to ifmap server: " + e);
				System.exit(1);
			}
			
			// TODO introduce Executor for thread handling
			Thread ssrcKeepaliveThread = new Thread(new Keepalive(ssrc,
							Integer.parseInt(Configuration.ifmapKeepalive())),
					"ssrc-keepalive-thread");
			
			hook.add(ssrcKeepaliveThread);
			watcher.add(ssrcKeepaliveThread);
			ssrcKeepaliveThread.start();
			
			
			
			if (Configuration.publisherEnable().equals("true")) {
				logger.info("activate publisher ...");
				runPublisher(ssrc, hook, watcher);
			}
			if (Configuration.subscriberEnable().equals("true")) {
				logger.info("activate subscriber ...");
				runSubscriber(ssrc, hook, watcher);
			}
			
			watcher.run(); // returns if one thread is not alive anymore
			hook.run();
			
			System.exit(1); // there is no way to exit with 0 at the moment
		}
	}
	
	/**
	 * Creates and starts the publisher part of ironvas based on the values
	 * in {@link Configuration}.
	 * 
	 * @param ssrc
	 * @param hook
	 * @param watcher
	 */
	public static void runPublisher(SSRC ssrc, ShutdownHook hook, ThreadInterruptionWatcher watcher) {
		Converter converter = createConverter(
				ssrc.getPublisherId(), "openvas@" + Configuration.openvasIP(),
				Configuration.updateFilter(), Configuration.notifyFilter());
		VulnerabilityHandler handler =
				new VulnerabilityHandler(ssrc, converter);

		OmpConnection omp = initOmp();
		
		VulnerabilityFetcher fetcher = new VulnerabilityFetcher(
				handler,
				omp,
				Integer.parseInt(Configuration.publishInterval()));

		Thread handlerThread = new Thread(handler,
				"handler-thread");
		Thread fetcherThread = new Thread(fetcher,
				"fetcher-thread");
		
		hook.add(handlerThread);
		hook.add(fetcherThread);
		
		watcher.add(handlerThread);
		watcher.add(fetcherThread);
		
		handlerThread.start();
		fetcherThread.start();
	}
	
	/**
	 * Creates and starts the subscriber part of ironvas based on the values
	 * in {@link Configuration}.
	 * 
	 * @param ssrc
	 * @param hook
	 * @param watcher
	 */
	public static void runSubscriber(SSRC ssrc, ShutdownHook hook, ThreadInterruptionWatcher watcher) {
		OmpConnection omp = initOmp();
		Subscriber subscriber = new Subscriber(
				omp,
				ssrc,
				Configuration.subscriberPdp(),
				Configuration.subscriberTargetNamePrefix(),
				Configuration.subscriberConfig());
		
		Thread subscriberThread = new Thread(subscriber, "subscriber-thread");
		
		hook.add(subscriberThread);
		watcher.add(subscriberThread);
		
		subscriberThread.start();
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
	public static Converter createConverter(String publisherId, String openvasId, String filterUpdate, String filterNotify) {
		FilterParser parser = new FilterParser();
		Map<RiskfactorLevel, Boolean> updateFilter = parser.parseLine(filterUpdate);
		Map<RiskfactorLevel, Boolean> notifyFilter = parser.parseLine(filterNotify);
		
		Converter converter = new FilterEventUpdateConverter(
				publisherId, openvasId, updateFilter, notifyFilter);
		return converter;
	}
	
	/**
	 * Creates a {@link SSRC} instance with the given configuration
	 * parameters.
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
	public static SSRC initIfmap(String authMethod, String basicUrl, String certUrl, String user, String pass, String keypath, String keypass) {
		SSRC ifmap = null;
		TrustManager[] tm = null;
		KeyManager[] km = null;
		
		try {
			tm = IfmapJHelper.getTrustManagers(Ironvas.class.getResourceAsStream(keypath), keypass);
			km = IfmapJHelper.getKeyManagers(Ironvas.class.getResourceAsStream(keypath), keypass);
		} catch (InitializationException e1) {
			e1.printStackTrace();
			System.exit(1);
		}

		try {
			if (authMethod.equals("basic")) {
				ifmap = new ThreadSafeSsrc(basicUrl, user, pass, tm);
			}
			else if (authMethod.equals("cert")) {
				ifmap = new ThreadSafeSsrc(certUrl, km, tm);
			}
			else {
				throw new IllegalArgumentException("unknown authentication method '"+authMethod+"'");
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
		return initIfmap(
				Configuration.ifmapAuthMethod(),
				Configuration.ifmapUrlBasic(),
				Configuration.ifmapUrlCert(),
				Configuration.ifmapBasicUser(),
				Configuration.ifmapBasicPassword(),
				Configuration.keyStorePath(),
				Configuration.keyStorePassword());
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
	public static OmpConnection initOmp(String ip, String port, String user, String pass, String keypath, String keypass) {
		OmpConnection omp = new OmpConnection(
				ip, 
				Integer.parseInt(port),
				user,
				pass,
				keypath,
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
		return initOmp(
				Configuration.openvasIP(),
				Configuration.openvasPort(),
				Configuration.openvasUser(),
				Configuration.openvasPassword(),
				Configuration.keyStorePath(),
				Configuration.keyStorePassword());
	}
	
	public static void setupLogging() {
		InputStream in = Ironvas.class.getResourceAsStream(LOGGING_CONFIG_FILE);
		
		try {
			LogManager.getLogManager().readConfiguration(in);
		} catch (Exception e) {
			System.err.println("could not read " + LOGGING_CONFIG_FILE + ", using defaults");
			Handler handler = new ConsoleHandler();
			Logger.getLogger("").addHandler(handler);
			Logger.getLogger("").setLevel(Level.INFO);
		}
		finally {
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

class ThreadList extends ArrayList<Thread> {}

class ShutdownHook extends ThreadList implements Runnable {

	@Override
	public void run() {
		for (Thread t : this) {
			t.interrupt();
		}
	}
}

class ThreadInterruptionWatcher extends ThreadList implements Runnable {

	@Override
	public void run() {
		boolean allAlive = true;
		while (allAlive) {
			for (Thread t : this) {
				if (!t.isAlive()) {
					allAlive = false;
				}
			}
			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				// we don't care about this special exception right here
			}
		}
	}
	
}
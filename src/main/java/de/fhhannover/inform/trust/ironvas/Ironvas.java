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
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import javax.net.ssl.TrustManager;

import de.fhhannover.inform.trust.ifmapj.IfmapJHelper;
import de.fhhannover.inform.trust.ifmapj.channel.SSRC;
import de.fhhannover.inform.trust.ifmapj.exception.InitializationException;
import de.fhhannover.inform.trust.ironvas.converter.Converter;
import de.fhhannover.inform.trust.ironvas.converter.FullEventUpdateConverter;
import de.fhhannover.inform.trust.ironvas.ifmap.Keepalive;
import de.fhhannover.inform.trust.ironvas.ifmap.ThreadSafeSsrc;
import de.fhhannover.inform.trust.ironvas.omp.OmpConnection;
import de.fhhannover.inform.trust.ironvas.omp.VulnerabilityFetcher;

/**
 * Ironvas is an IF-MAP client which integrates OpenVAS into an IF-MAP
 * environment.
 * 
 * @author Ralf Steuerwald
 *
 */
public class Ironvas {
	
	private static final String LOGGING_CONFIG_FILE = "/logging.properties";
	
	public static void main(String[] args) {
		setupLogging();
		Configuration.init();
		
		// TODO command line parser
		// overwrite configuration with command line arguments

		// ifmap
		String ifmapurl     = Configuration.get(Configuration.MAPS_URL_BASIC_AUTH);
		String ifmapuser    = Configuration.get(Configuration.MAPS_AUTH_BASIC_USER);
		String ifmappass    = Configuration.get(Configuration.MAPS_AUTH_BASIC_PASSWORD);
		String ifmapkeypath = Configuration.get(Configuration.KEYSTORE_PATH);
		String ifmapkeypass = Configuration.get(Configuration.KEYSTORE_PASSWORD);

		// omp
		String ompip      = Configuration.get(Configuration.OPENVAS_IP);
		String ompport    = Configuration.get(Configuration.OPENVAS_OMP_PORT);
		String ompuser    = Configuration.get(Configuration.OPENVAS_OMP_USER);
		String omppass    = Configuration.get(Configuration.OPENVAS_OMP_PASSWORD);
		String ompkeypath = Configuration.get(Configuration.KEYSTORE_PATH);
		String ompkeypass = Configuration.get(Configuration.KEYSTORE_PASSWORD);

		// misc
		String discovererId    = "openvas@"+ Configuration.get(Configuration.OPENVAS_IP);
		String publishInterval = Configuration.get(Configuration.OMP_INTERVAL);
		String ifmapKeepalive  = Configuration.get(Configuration.IFMAP_INTERVAL);
		
		
		// begin initialization ------------------------------------------------
		
		// ifmap
		SSRC ssrc = createIfmapService(ifmapurl, ifmapuser, ifmappass, ifmapkeypath, ifmapkeypass);
		try {
			ssrc.newSession();
			ssrc.purgePublisher();
		} catch (Exception e) {
			System.err.println("could not connect to ifmap server: " + e);
			System.exit(1);
		}
		
		// omp
		OmpConnection omp = createOmpConnection(ompip, ompport, ompuser, omppass, ompkeypath, ompkeypass);
		
		// ironvas
		Converter converter = createConverter(
				ssrc.getPublisherId(), discovererId);
		VulnerabilityHandler handler =
				new VulnerabilityHandler(ssrc, converter);

		VulnerabilityFetcher fetcher = new VulnerabilityFetcher(
				handler,
				omp,
				Integer.parseInt(publishInterval));

		// threads
		final Thread handlerThread = new Thread(handler,
				"handler-thread");
		final Thread fetcherThread = new Thread(fetcher,
				"fetcher-thread");
		final Thread ssrcKeepaliveThread = new Thread(
				new Keepalive(
						ssrc,
						Integer.parseInt(ifmapKeepalive)),
				"ssrc-keepalive-thread");
		
		Runnable interrupter = new Runnable() {
			public void run() {
				handlerThread.interrupt();
				fetcherThread.interrupt();
				ssrcKeepaliveThread.interrupt();
			}
		};
		
		Runtime.getRuntime().addShutdownHook(new Thread(interrupter));
		
		ssrcKeepaliveThread.start();
		handlerThread.start();
		fetcherThread.start();

		while (
				handlerThread.isAlive() &&
				fetcherThread.isAlive() &&
				ssrcKeepaliveThread.isAlive()) {
			try {
				Thread.sleep(2000);
			} catch (InterruptedException e) {
				// we don't care about this special exception right here
			}
		}
		// interrupt the remaining thread
		interrupter.run();
		
		try {
			handlerThread.join();
			fetcherThread.join();
			ssrcKeepaliveThread.join();
		} catch (InterruptedException e) {
			System.err.println("interruped while waiting for termination of worker threads");
			System.exit(1);
		}
		System.exit(0);
	}
	
	public static SSRC createIfmapService(String url, String user, String pass, String keypath, String keypass) {
		SSRC ifmap = null;
		TrustManager[] tm = null;
		
		try {
			tm = IfmapJHelper.getTrustManagers(Ironvas.class.getResourceAsStream(keypath), keypass);
		} catch (InitializationException e1) {
			e1.printStackTrace();
			System.exit(1);
		}
		
		try {
			ifmap = new ThreadSafeSsrc(url, user, pass, tm);
		} catch (InitializationException e) {
			e.printStackTrace();
			System.exit(1);
		}
		return ifmap;
	}
	
	public static OmpConnection createOmpConnection(String ip, String port, String user, String pass, String keypath, String keypass) {
		OmpConnection omp = new OmpConnection(
				ip, 
				Integer.parseInt(port),
				user,
				pass,
				keypath,
				keypass);
		return omp;
	}
	
	public static Converter createConverter(String publisherId, String openvasId) {
		Converter converter = new FullEventUpdateConverter(
				publisherId,
				openvasId);
		return converter;
	}
	
	public static void setupLogging() {
		InputStream in = Ironvas.class.getResourceAsStream(LOGGING_CONFIG_FILE);
		
		try {
			LogManager.getLogManager().readConfiguration(in);
		} catch (Exception e) {
			System.err.println("ERROR: unable to read logging configuration!");
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

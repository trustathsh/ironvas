/*
 * #%L ===================================================== _____ _ ____ _ _ _ _ |_ _|_ __ _ _ ___| |_ / __ \| | | |
 * ___ | | | | | | | '__| | | / __| __|/ / _` | |_| |/ __|| |_| | | | | | | |_| \__ \ |_| | (_| | _ |\__ \| _ | |_| |_|
 * \__,_|___/\__|\ \__,_|_| |_||___/|_| |_| \____/
 * 
 * =====================================================
 * 
 * Hochschule Hannover (University of Applied Sciences and Arts, Hannover) Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de Website: http://trust.f4.hs-hannover.de
 * 
 * This file is part of ironvas, version 0.1.7, implemented by the Trust@HsH research group at the Hochschule Hannover.
 * %% Copyright (C) 2011 - 2016 Trust@HsH %% Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License. #L%
 */
package de.hshannover.f4.trust.ironvas;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.concurrent.TimeoutException;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.Connection;

import de.hshannover.f4.trust.ifmapj.IfmapJ;
import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.config.BasicAuthConfig;
import de.hshannover.f4.trust.ifmapj.config.CertAuthConfig;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.exception.InitializationException;
import de.hshannover.f4.trust.ifmapj.messages.PublishRequest;
import de.hshannover.f4.trust.ironvas.converter.Converter;
import de.hshannover.f4.trust.ironvas.ifmap.Keepalive;
import de.hshannover.f4.trust.ironvas.ifmap.SelfPublisher;
import de.hshannover.f4.trust.ironvas.omp.OmpConnection;
import de.hshannover.f4.trust.ironvas.omp.VulnerabilityFetcher;
import de.hshannover.f4.trust.ironvas.subscriber.Subscriber;

/**
 * Ironvas is an IF-MAP client which integrates OpenVAS into an IF-MAP environment.
 *
 * @author Ralf Steuerwald
 *
 */
public class Ironvas implements Runnable {

	private static final Logger LOGGER = Logger.getLogger(Ironvas.class
			.getName());
	private static final String LOGGING_CONFIG_FILE = "/logging.properties";

	private SSRC mSsrc;
	private OmpConnection mOmp;
	private Keepalive mSsrcKeepalive;
	private Connection mAmqpConnection;

	private Converter mConverter;
	private VulnerabilityHandler mHandler;
	private VulnerabilityFetcher mFetcher;
	private AmqpPublisher mAmqpPublisher;

	private Subscriber mSubscriber;

	private Thread mHandlerThread;
	private Thread mFetcherThread;
	private Thread mSubscriberThread;
	private Thread mSsrcKeepaliveThread;
	private Thread mAmqpPublisherThread;

	private ShutdownHook mShutdownHook;

	/**
	 * Initializes all ironvas components based on the parameter in {@link Configuration}, therefore the
	 * {@link Configuration} must be loaded before calling this constructor.
	 */
	public Ironvas() {
		mSsrc = initIfmap();
		mOmp = initOmp();
		mShutdownHook = new ShutdownHook();
		mAmqpPublisher = null;
		
		try {
			mSsrc.newSession();
			mSsrc.purgePublisher();

		} catch (Exception e) {
			System.err.println("could not connect to ifmap server: "
					+ e);
			System.exit(1);
		}
		
		if(Configuration.eventstreamEnable().equals("true")){  // String if it later gets a both feature
			mAmqpConnection = initAMQP();
			mAmqpPublisher = new AmqpPublisher(mAmqpConnection, Configuration.amqpExchangeName(), mSsrc.getPublisherId());
			mAmqpPublisherThread = new Thread(mAmqpPublisher, "amqp-publischer-thread");
			mShutdownHook.add(mAmqpPublisherThread);
		}		
		
		mSsrcKeepalive = new Keepalive(mSsrc, Configuration.ifmapKeepalive());

		mConverter = createConverter(mSsrc, mOmp);
		mHandler = new VulnerabilityHandler(mSsrc, mConverter, Configuration.selfPublishDevice(),
				Configuration.eventstreamEnable());
		
		VulnerabilityFilter vulnerabilityFilter = null;
		try {
			vulnerabilityFilter = new ScriptableFilter();
			mFetcher = new VulnerabilityFetcher(mHandler, mOmp,
					Configuration.publishInterval(), mAmqpPublisher, vulnerabilityFilter);
		} catch (FilterInitializationException e) {
			LOGGER.warning("could not load filter.js, falling back to no filtering");
			mFetcher = new VulnerabilityFetcher(mHandler, mOmp,
					Configuration.publishInterval(),mAmqpPublisher);
		}

		mSubscriber = new Subscriber(mOmp, mSsrc, Configuration.subscriberPdp(),
				Configuration.subscriberNamePrefix(),
				Configuration.subscriberConfig());

		// TODO: introduce supervisor thread to control the different sub-threads (clean exit, error handling, ...)
		mHandlerThread = new Thread(mHandler, "handler-thread");
		mFetcherThread = new Thread(mFetcher, "fetcher-thread");
		mSubscriberThread = new Thread(mSubscriber, "subscriber-thread");
		mSsrcKeepaliveThread = new Thread(mSsrcKeepalive, "ssrc-keepalive-thread");
		
		mShutdownHook.add(mHandlerThread);
		mShutdownHook.add(mFetcherThread);
		mShutdownHook.add(mSubscriberThread);		
		mShutdownHook.add(mSsrcKeepaliveThread);
		
		Runtime.getRuntime().addShutdownHook(new Thread(mShutdownHook));
	}

	@Override
	public void run() {
		if (!Configuration.publisherEnable()
				&& !Configuration.subscriberEnable()) {
			LOGGER.warning("nothing to do, shutting down ...");
			System.exit(0);
		}

		mSsrcKeepaliveThread.start();

		if (Configuration.publisherEnable()) {
			if (Configuration.selfPublishEnable()) {
				LOGGER.info("active self-publisher ...");
				String ipValue = Configuration.openvasIp();
				String deviceName = Configuration.selfPublishDevice();

				String serviceName = "openvas";
				String serviceType = "vulnerability scanner";
				String servicePort = Integer.toString(Configuration.openvasPort());
				String implementationName = "OpenVAS";
				String implementationVersion = Configuration.openvasVersion();
				String implementationPlatform = null;
				String implementationPatch = null;
				String administrativeDomain = "";
				PublishRequest selfPublishRequest = SelfPublisher.createSelfPublishRequest(ipValue, deviceName,
						serviceName, serviceType, servicePort,
						implementationName, implementationVersion, implementationPlatform, implementationPatch,
						administrativeDomain);
				try {
					mSsrc.publish(selfPublishRequest);
				} catch (IfmapErrorResult e) {
					System.err.println("could not publish self-information: "
							+ e);
				} catch (IfmapException e) {
					System.err.println("could not publish self-information: "
							+ e);
				}
			}

			LOGGER.info("activate publisher ...");
			mHandlerThread.start();
			mFetcherThread.start();
			
			if(Configuration.eventstreamEnable().equals("true")){
				LOGGER.info("activate AMQP publisher ...");
				mAmqpPublisherThread.start();
			}
		}
		if (Configuration.subscriberEnable()) {
			LOGGER.info("activate subscriber ...");
			mSubscriberThread.start();
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
	 * Creates a {@link Converter} instance with the given configuration parameters.
	 *
	 * @param publisherId
	 * @param openvasId
	 * @param filterUpdate
	 * @param filterNotify
	 * @return
	 */
	public static Converter createConverter(SSRC ssrc, OmpConnection omp) {
		Context context = new Context(ssrc, "openvas@"
				+ omp.host());

		Converter converter = null;
		String className = Configuration.converterName();

		LOGGER.info("try to load '"
				+ className + "'");
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
				throw new RuntimeException("'"
						+ className + "' does not "
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
		int initialConnectionTimeout = 120
				* 1000;
		try {
			if (authMethod.equals("basic")) {
				BasicAuthConfig config = new BasicAuthConfig(basicUrl, user,
						pass, keypath, keypass, true, initialConnectionTimeout);
				return IfmapJ.createSsrc(config);
			} else if (authMethod.equals("cert")) {
				CertAuthConfig config = new CertAuthConfig(certUrl, keypath,
						keypass, keypath, keypass, true,
						initialConnectionTimeout);
				return IfmapJ.createSsrc(config);
			} else {
				throw new IllegalArgumentException(
						"unknown authentication method '"
								+ authMethod + "'");
			}
		} catch (InitializationException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Creates a {@link SSRC} instance based on the values in {@link Configuration}.
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
	 * Creates an {@link omp.OmpConnection} instance with the given configuration parameters.
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
	 * Creates an {@link omp.OmpConnection} instane based on the values in {@link Configuration}.
	 *
	 * @return
	 */
	public static OmpConnection initOmp() {
		return initOmp(Configuration.openvasIp(), Configuration.openvasPort(),
				Configuration.openvasUser(), Configuration.openvasPassword(),
				Configuration.keyStorePath(), Configuration.keyStorePassword());
	}

	/**
	 * Creates a {@link AMQP} instance with the given configuration parameters.
	 *
	 * @param eventStreamEnabled
	 * @param tlsEnable
	 * @param userName
	 * @param password
	 * @param virtualHost
	 * @param hostName
	 * @param portNumber
	 * @param keyStorePath
	 * @param keyStorePassword
	 * @return 
	 */
	public static Connection initAMQP(String eventStreamEnabled, boolean tlsEnable, String userName, String password,
			String virtualHost, String hostName, Integer portNumber, String keyStorePath, String keyStorePassword) {
		
		Connection connection = null;
		ConnectionFactory factory = new ConnectionFactory();
		factory.setUsername(userName);
		factory.setPassword(password);
		factory.setVirtualHost(virtualHost);
		factory.setHost(hostName);
		factory.setPort(portNumber);
		if(eventStreamEnabled.equals("true")){
			if(tlsEnable){
				try {
				
			        KeyStore tks = KeyStore.getInstance("JKS");
			        tks.load(Ironvas.class.getResourceAsStream(keyStorePath), keyStorePassword.toCharArray());
			
			        TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			        tmf.init(tks);
			
			        SSLContext c = SSLContext.getInstance("TLSv1.2");
			        c.init(null, tmf.getTrustManagers(), null);
			        factory.useSslProtocol(c);
			        
				} catch (KeyStoreException e1) {
					LOGGER.severe("Cannot establish connection to AMQP, shutting down ..."+ e1);
				} catch (NoSuchAlgorithmException e) {
					LOGGER.severe("Cannot establish connection to AMQP, shutting down ..."+ e);
				} catch (CertificateException e) {
					LOGGER.severe("Cannot establish connection to AMQP, shutting down ..."+ e);
				} catch (FileNotFoundException e) {
					LOGGER.severe("Cannot establish connection to AMQP, shutting down ..."+ e);
				} catch (IOException e) {
					LOGGER.severe("Cannot establish connection to AMQP, shutting down ..."+ e);
				} catch (KeyManagementException e) {
					LOGGER.severe("Cannot establish connection to AMQP, shutting down ..."+ e);
				}
				
			}
			try {
				connection = factory.newConnection();
			} catch (IOException e) {
				LOGGER.severe("Cannot establish connection to AMQP, shutting down ..."+ e);
				System.exit(1);
			} catch (TimeoutException e) {
				LOGGER.severe("Cannot establish connection to AMQP, shutting down ..."+ e);
				System.exit(1);
			}			
			
		}		

		return connection;

	}

	/**
	 * Creates an {@link AMQP.Connection} instance based on the values in {@link Configuration}.
	 *
	 * @return
	 */
	public static Connection initAMQP() {
		return initAMQP(Configuration.eventstreamEnable(), Configuration.amqpTlsEnable(), Configuration.amqpUserName(), Configuration.amqpPassword(),
				Configuration.amqpVirtualHost(), Configuration.amqpIp(),
				Integer.parseInt(Configuration.amqpPort()), Configuration.keyStorePath(), Configuration.keyStorePassword() );
	}

	public static void setupLogging() {
		InputStream in = Ironvas.class.getResourceAsStream(LOGGING_CONFIG_FILE);

		try {
			LogManager.getLogManager().readConfiguration(in);
		} catch (Exception e) {
			System.err.println("could not read "
					+ LOGGING_CONFIG_FILE
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

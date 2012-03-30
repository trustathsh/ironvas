package de.fhhannover.inform.trust.ironvas;

import java.io.InputStream;
import java.util.logging.LogManager;

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
		
		SSRC ssrc = createIfmapService();
		try {
			ssrc.newSession();
		} catch (Exception e) {
			System.err.println("could not connect to ifmap server: " + e);
			System.exit(1);
		}
		
		OmpConnection omp = createOmpConnection();
		
		Converter converter = createConverter(
				ssrc.getPublisherId(),
				"openvas@"+ Configuration.get(Configuration.OPENVAS_IP));
		VulnerabilityHandler handler =
				new VulnerabilityHandler(ssrc, converter);

		VulnerabilityFetcher fetcher = new VulnerabilityFetcher(
				handler,
				omp,
				Integer.parseInt(Configuration.get(Configuration.OMP_INTERVAL)));

		final Thread handlerThread = new Thread(handler,
				"handler-thread");
		final Thread fetcherThread = new Thread(fetcher,
				"fetcher-thread");
		final Thread ssrcKeepaliveThread = new Thread(
				new Keepalive(
						ssrc,
						Integer.parseInt(Configuration.get(Configuration.IFMAP_INTERVAL))),
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
	
	public static SSRC createIfmapService() {
		SSRC ifmap = null;
		String url = Configuration.get(Configuration.MAPS_URL_BASIC_AUTH);
		String user = Configuration.get(Configuration.MAPS_AUTH_BASIC_USER);
		String pass = Configuration.get(Configuration.MAPS_AUTH_BASIC_PASSWORD);
		String keypath = Configuration.get(Configuration.KEYSTORE_PATH);
		String keypass = Configuration.get(Configuration.KEYSTORE_PASSWORD);
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
	
	public static OmpConnection createOmpConnection() {
		OmpConnection omp = new OmpConnection(
				Configuration.get(Configuration.OPENVAS_IP), 
				Integer.parseInt(Configuration.get(Configuration.OPENVAS_OMP_PORT)),
				Configuration.get(Configuration.OPENVAS_OMP_USER),
				Configuration.get(Configuration.OPENVAS_OMP_PASSWORD),
				Configuration.get(Configuration.KEYSTORE_PATH),
				Configuration.get(Configuration.KEYSTORE_PASSWORD));
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
		}
	}

}

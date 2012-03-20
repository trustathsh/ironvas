package de.fhhannover.inform.trust.ironvas.ifmap;

import java.util.logging.Logger;

import de.fhhannover.inform.trust.ifmapj.channel.SSRC;
import de.fhhannover.inform.trust.ifmapj.exception.IfmapErrorResult;
import de.fhhannover.inform.trust.ifmapj.exception.IfmapException;

public class Keepalive implements Runnable {
	
	private static final Logger logger =
			Logger.getLogger(Keepalive.class.getName());

	private SSRC ssrc;
	
	/**
	 * The interval between the renewSession requests in seconds. Must be
	 * smaller than the session timeout value.
	 */
	private int interval;
	
	public Keepalive(SSRC ssrc, int interval) {
		this.ssrc = ssrc;
		this.interval = interval;
	}

	@Override
	public void run() {
		try {
			while (!Thread.currentThread().isInterrupted()) {
				logger.fine("sending renewSession");
				ssrc.renewSession();
				Thread.sleep(interval * 1000);
			}
		} catch (IfmapException e) {
			// Catch every exception originated in ifmapj and stop running.
			
			// TODO: Future implementation/enhancements may notify the
			// other threads about the failed ifmap operation (after a
			// successful reconnect), so that they have the chance to
			// restore their ifmap status (publish or subscribe again).
			
			logger.severe("renewSession failed: " + e.getMessage());
		} catch (IfmapErrorResult e) {
			logger.severe("renewSession failed: " + e.getMessage());
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
			logger.info("wakup by interrupt signal, exiting ...");
		}
		finally {
			try {
				ssrc.endSession();
			} catch (Exception e) {
				logger.warning("error while ending the session");
			}
			logger.info("shutdown complete.");
		}
	}
}

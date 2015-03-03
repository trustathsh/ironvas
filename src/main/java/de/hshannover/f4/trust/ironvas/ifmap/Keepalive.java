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
 * This file is part of ironvas, version 0.1.5, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2011 - 2015 Trust@HsH
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
package de.hshannover.f4.trust.ironvas.ifmap;

import java.util.logging.Logger;

import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;

/**
 * A {@link Keepalive} can be used to keep an IF-MAP connection alive, by
 * continuously sending a re-new session request to the MAPS.
 *
 * @author Ralf Steuerwald
 *
 */
public class Keepalive implements Runnable {

    private static final Logger LOGGER = Logger.getLogger(Keepalive.class
            .getName());

    private SSRC mSsrc;

    /**
     * The interval between the renewSession requests in seconds. Must be
     * smaller than the session timeout value.
     */
    private int mInterval;

    /**
     * Creates a new {@link Keepalive} object which can be used to keep
     * the connection associated with the given {@link SSRC} alive. The
     * connection has to be established before.
     *
     * @param ssrc      the session to keep alive
     * @param interval  the interval in which re-new session request will be
     *                   send
     */
    public Keepalive(SSRC ssrc, int interval) {
        this.mSsrc = ssrc;
        this.mInterval = interval;
    }

    @Override
    public void run() {
        try {
            while (!Thread.currentThread().isInterrupted()) {
                LOGGER.fine("sending renewSession");
                mSsrc.renewSession();
                Thread.sleep(mInterval * 1000);
            }
        } catch (IfmapException e) {
            LOGGER.severe("renewSession failed: " + e.getMessage());
        } catch (IfmapErrorResult e) {
            LOGGER.severe("renewSession failed: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.info("wakup by interrupt signal, exiting ...");
        } finally {
            try {
                mSsrc.endSession();
            } catch (Exception e) {
                LOGGER.warning("error while ending the session");
            }
            LOGGER.info("shutdown complete.");
        }
    }
}

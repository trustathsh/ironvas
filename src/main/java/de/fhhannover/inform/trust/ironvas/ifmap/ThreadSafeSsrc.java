package de.fhhannover.inform.trust.ironvas.ifmap;

/*
 * #%L
 * ====================================================
 *   _____                _     ____  _____ _   _ _   _
 *  |_   _|_ __ _   _ ___| |_  / __ \|  ___| | | | | | |
 *    | | | '__| | | / __| __|/ / _` | |_  | |_| | |_| |
 *    | | | |  | |_| \__ \ |_| | (_| |  _| |  _  |  _  |
 *    |_| |_|   \__,_|___/\__|\ \__,_|_|   |_| |_|_| |_|
 *                             \____/
 * 
 * =====================================================
 * 
 * Fachhochschule Hannover 
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.inform.fh-hannover.de/
 * 
 * This file is part of ironvas, version 0.1.1, implemented by the Trust@FHH 
 * research group at the Fachhochschule Hannover.
 * 
 * ironvas is a *highly experimental* integration of Open Vulnerability Assessment 
 * System (OpenVAS) into a MAP-Infrastructure. The integration aims to share security 
 * related informations (vulnerabilities detected by OpenVAS) with other network 
 * components in the TNC architecture via IF-MAP.
 * %%
 * Copyright (C) 2011 - 2013 Trust@FHH
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

import javax.net.ssl.KeyManager;
import javax.net.ssl.TrustManager;

import de.fhhannover.inform.trust.ifmapj.IfmapJ;
import de.fhhannover.inform.trust.ifmapj.channel.ARC;
import de.fhhannover.inform.trust.ifmapj.channel.SSRC;
import de.fhhannover.inform.trust.ifmapj.exception.CommunicationException;
import de.fhhannover.inform.trust.ifmapj.exception.IfmapErrorResult;
import de.fhhannover.inform.trust.ifmapj.exception.IfmapException;
import de.fhhannover.inform.trust.ifmapj.exception.InitializationException;
import de.fhhannover.inform.trust.ifmapj.messages.PublishRequest;
import de.fhhannover.inform.trust.ifmapj.messages.Request;
import de.fhhannover.inform.trust.ifmapj.messages.Result;
import de.fhhannover.inform.trust.ifmapj.messages.SearchRequest;
import de.fhhannover.inform.trust.ifmapj.messages.SearchResult;
import de.fhhannover.inform.trust.ifmapj.messages.SubscribeRequest;

/**
 * This class wraps a {@link SSRC} in a thread safe manner.
 *
 * @author Ralf Steuerwald
 *
 */
public class ThreadSafeSsrc implements SSRC {

    private SSRC ssrc;

    /**
     * Creates a new thread safe {@link SSRC}.
     *
     * @param url
     *            the url to connect to
     * @param user
     *            basic authentication user
     * @param pass
     *            basic authentication password
     * @param tms
     *            TrustManager to initialize the {@link SSLContext}
     * @throws InitializationException
     */
    public ThreadSafeSsrc(String url, String user, String pass,
            TrustManager[] tms) throws InitializationException {
        ssrc = IfmapJ.createSSRC(url, user, pass, tms);
    }

    public ThreadSafeSsrc(String url, KeyManager[] kms, TrustManager[] tms)
            throws InitializationException {
        ssrc = IfmapJ.createSSRC(url, kms, tms);
    }

    @Override
    public synchronized String getSessionId() {
        return ssrc.getSessionId();
    }

    @Override
    public synchronized void setSessionId(String sessionId) {
        ssrc.setSessionId(sessionId);
    }

    @Override
    public synchronized String getPublisherId() {
        return ssrc.getPublisherId();
    }

    @Override
    public synchronized void setPublisherId(String publisherId) {
        ssrc.setPublisherId(publisherId);
    }

    @Override
    public synchronized Integer getMaxPollResSize() {
        return ssrc.getMaxPollResSize();
    }

    @Override
    public synchronized void setMaxPollResSize(Integer mprs) {
        ssrc.setMaxPollResSize(mprs);
    }

    @Override
    public synchronized void closeTcpConnection() throws CommunicationException {
        ssrc.closeTcpConnection();
    }

    @Override
    public synchronized void setGzip(boolean useGzip) {
        ssrc.setGzip(useGzip);
    }

    @Override
    public synchronized boolean usesGzip() {
        return ssrc.usesGzip();
    }

    @Override
    public synchronized Result genericRequest(Request req)
            throws IfmapErrorResult, IfmapException {
        return ssrc.genericRequest(req);
    }

    @Override
    public synchronized Result genericRequestWithSessionId(Request req)
            throws IfmapErrorResult, IfmapException {
        return ssrc.genericRequestWithSessionId(req);
    }

    @Override
    public synchronized void newSession() throws IfmapErrorResult,
            IfmapException {
        ssrc.newSession();
    }

    @Override
    public synchronized void newSession(Integer maxPollResSize)
            throws IfmapErrorResult, IfmapException {
        ssrc.newSession(maxPollResSize);
    }

    @Override
    public synchronized void endSession() throws IfmapErrorResult,
            IfmapException {
        ssrc.endSession();
    }

    @Override
    public synchronized void renewSession() throws IfmapErrorResult,
            IfmapException {
        ssrc.renewSession();
    }

    @Override
    public synchronized void purgePublisher() throws IfmapErrorResult,
            IfmapException {
        ssrc.purgePublisher();
    }

    @Override
    public synchronized void purgePublisher(String publisherId)
            throws IfmapErrorResult, IfmapException {
        ssrc.purgePublisher(publisherId);
    }

    @Override
    public synchronized void publish(PublishRequest req)
            throws IfmapErrorResult, IfmapException {
        ssrc.publish(req);
    }

    @Override
    public synchronized void subscribe(SubscribeRequest req)
            throws IfmapErrorResult, IfmapException {
        ssrc.subscribe(req);
    }

    @Override
    public synchronized SearchResult search(SearchRequest req)
            throws IfmapErrorResult, IfmapException {
        return ssrc.search(req);
    }

    @Override
    public synchronized ARC getArc() throws InitializationException {
        return ssrc.getArc();
    }

}

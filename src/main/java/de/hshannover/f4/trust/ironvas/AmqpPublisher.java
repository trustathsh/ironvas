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
 * This file is part of ironvas, version 0.1.7, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2011 - 2016 Trust@HsH
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

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeoutException;
import java.util.logging.Logger;

import org.apache.commons.lang3.SerializationUtils;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;


public class AmqpPublisher implements Runnable {
	
	
	
	private LinkedBlockingQueue<Report> mWorkQueue = new LinkedBlockingQueue<Report>();
	
	private Channel mAmqpChannel;
	private String mExhangeName;
	protected VulnerabilityCache mCache = new VulnerabilityCache();
	
	private static final Logger LOGGER = Logger
			.getLogger(VulnerabilityHandler.class.getName());
	
	
	public AmqpPublisher(Connection connection, String exhangeName ) {
		mExhangeName = exhangeName;
		try {
			mAmqpChannel = connection.createChannel();
		} catch (IOException e) {
			LOGGER.severe("Can't open AMQP connection, exiting ...");
			System.exit(1);
		}
	}

	@Override
	public void run() {
		LOGGER.info("starting "
				+ this.getClass().getSimpleName());

		try {
			while (!Thread.currentThread().isInterrupted()) {
				Report lastReport = mWorkQueue.take();
				onNewReport(lastReport);
			}
		} catch (InterruptedException e) {
			try {
				mAmqpChannel.close();
			} catch (IOException e1) {
				LOGGER.info("soft shutdown don't work, exiting hard ...");
			} catch (TimeoutException e1) {
				LOGGER.info("soft shutdown don't work, exiting hard ...");
			}
			Thread.currentThread().interrupt();
			LOGGER.info("got interrupt signal while waiting for new work, exiting ...");
		} finally {
			LOGGER.info("shutdown complete.");
		}
		
	}
	
	public void onNewReport(Report report) {
		
		String taskId = report.mTaskId;
		
		List<Vulnerability> vulnerabilities = report.mVulnerabilities;		
		Set<Vulnerability> news = mCache.indicateNew(taskId, vulnerabilities);
		Set<Vulnerability> outDated = mCache.indicateOutDated(taskId,
				vulnerabilities);
		updateCache(taskId, news, outDated);
				
		if (!news.isEmpty()){
			
			try {
				
				for (Vulnerability vul : news){
										
					IronvasEvent event = new IronvasEvent(vul.getId(), 
							vul.getTimestamp(),
							vul.getSubnet(), 
							vul.getHost(), 
							vul.getPort(), 
							vul.getThreat(), 
							vul.getDescription(), 
							vul.getNvt().getOid(),
							vul.getNvt().getName(),
							vul.getNvt().getCvssBase(),
							vul.getNvt().getRiskFactor(),
							vul.getNvt().getCve(),
							vul.getNvt().getBid()
							);
							
					byte[] eventData = SerializationUtils.serialize(event);
					
					mAmqpChannel.basicPublish(mExhangeName, "", null, eventData);					
				}				
				
			} catch (IOException e) {
				LOGGER.severe("Can't publish IronvasEvent to AMQP exchanger");
			}
		}	
	}
	
	public void updateCache(String taskId, Set<Vulnerability> news,
			Set<Vulnerability> outDated) {
		mCache.removeFromTask(taskId, outDated);
		mCache.addToTask(taskId, news);
	}
	
	
	/**
	 * Submit a list of vulnerabilities to this {@link VulnerabilityHandler}.
	 *
	 * @param lastReport
	 *            the {@link Report} containing the vulnerabilities
	 */
	public void submit(Report lastReport) {
		try {
			mWorkQueue.put(lastReport);
		} catch (InterruptedException e) {
			LOGGER.severe("could not submit vulnerabilities to handler "
					+ e.getMessage());
		}
	}

}

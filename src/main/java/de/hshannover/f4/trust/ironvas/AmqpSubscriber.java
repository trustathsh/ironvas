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
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.Consumer;
import com.rabbitmq.client.DefaultConsumer;
import com.rabbitmq.client.Envelope;

import de.decoit.clearer.event.common.BoltEvent;
import de.hshannover.f4.trust.clearer.event.ironvas.IronvasDeleteTaskEvent;
import de.hshannover.f4.trust.clearer.event.ironvas.IronvasScanEvent;
import de.hshannover.f4.trust.clearer.event.ironvas.IronvasTaskInformation;
import de.hshannover.f4.trust.ironvas.omp.Config;
import de.hshannover.f4.trust.ironvas.omp.OmpConnection;
import de.hshannover.f4.trust.ironvas.omp.Target;
import de.hshannover.f4.trust.ironvas.omp.Task;
import scala.collection.Iterator;
import scala.collection.Seq;

/**
 * The <code>AmqpSubscriber</code> is responsible for handling event for creating and deleting OpenVAS scans.
 *
 * @author Marcel Felix
 *
 */
public class AmqpSubscriber {

	private final Connection mAmqpConnection;
	private final OmpConnection mOmp;
	private Channel mAmqpChannel;
	private final String mQueueName;
	private final boolean mDurable;
	private final String mConfigName;
	private Config mDefaultOpenVASTaskConfig = null;

	private final Map<String, Config> mConfigCache = new HashMap<>();
	private final ObjectMapper mObjMapper;
	protected VulnerabilityCache mCache = new VulnerabilityCache();

	private static final Logger LOGGER = Logger.getLogger(VulnerabilityHandler.class.getName());

	/**
	 * Creates and starts a new AmqpSubscriber.
	 * 
	 * @param mOmp
	 *            Connection to the OpenVAS Server
	 * @param connection
	 *            Connection to the AMQP Server
	 * @param queueName
	 *            name of the amqp queue that will be used.
	 * @param durable
	 *            true of the queue should be durable
	 * @param defaultConfigName
	 *            name of the default configuration that will be used. The default configuration will be used as a
	 *            fallback. If a configuration with this name can't be found, the AMQP Subscriber will shut down.
	 */
	public AmqpSubscriber(OmpConnection mOmp, Connection connection, String queueName, boolean durable,
			String defaultConfigName) {
		LOGGER.info("Created AmqpSubscriber");
		this.mOmp = mOmp;
		this.mAmqpConnection = connection;
		this.mQueueName = queueName;
		this.mConfigName = defaultConfigName;
		this.mDurable = durable;
		CBORFactory fac = new CBORFactory();
		mObjMapper = new ObjectMapper(fac);

		initSubscriber();
	}

	/**
	 * Initiates the amqp channel for the set QueueName and with the set durability
	 */
	private void initChannel() {
		try {
			mAmqpChannel = mAmqpConnection.createChannel();
			mAmqpChannel.queueDeclare(mQueueName, mDurable, false, false, null);
			mAmqpChannel.basicConsume(mQueueName, false, getDefaultConsumer());
		} catch (IOException e) {
			e.printStackTrace();
			LOGGER.severe("Can't open AMQP connection, exiting ...");
			System.exit(1);
		}
	}

	/**
	 * Creates a Consumer which handles the following events:
	 * 
	 * - IronvasScanEvent: 
	 * 					Creates a task for the given TaskInformation. A target will be created if no corresponding
	 * 					target exists. 
	 * - IronvasDeleteTaskEvent: 
	 * 					Deletes the tasks for the given list of TaskInformation. If no
	 * 					corresponding task can be found, it will be ignored. * - Unknown events/objects: Will be acknowledged, but not
	 * 					processed.
	 * 
	 * @return the consumer
	 */
	private Consumer getDefaultConsumer() {
		return new DefaultConsumer(mAmqpChannel) {
			@Override
			public void handleDelivery(String consumerTag, Envelope envelope, AMQP.BasicProperties properties,
					byte[] body) throws IOException {

				try {
					if (properties.getContentType() == null
							|| !properties.getContentType().equals("application/cbor")) {
						LOGGER.info("Got message with wrong content type. Ignoring it.");
						mAmqpChannel.basicAck(envelope.getDeliveryTag(), false);
						return;
					}
					BoltEvent event = null;

					try {
						event = mObjMapper.readValue(body, IronvasScanEvent.class);
					} catch (Exception e1) {
						try {
							event = mObjMapper.readValue(body, IronvasDeleteTaskEvent.class);
						} catch (Exception e2) {
						}
					}

					if (event instanceof IronvasScanEvent) {
						handleEvent((IronvasScanEvent) event);
					} else if (event instanceof IronvasDeleteTaskEvent) {
						if (Configuration.amqpSubscribeAllowDeleteEvent()) {
							handleEvent((IronvasDeleteTaskEvent) event);
						}
					} else {
						LOGGER.info("Received unknown Event. Delivery Tag:"
								+ envelope.getDeliveryTag());
					}

				} catch (Exception e) {
					e.printStackTrace();
					LOGGER.info("Received message is no "
							+ IronvasScanEvent.class.getName() + " Event");
				} finally {
					mAmqpChannel.basicAck(envelope.getDeliveryTag(), false);
				}
			}

		};
	}

	/**
	 * Processes an IronvasDeleteTaskEvent.
	 * This will try to delete all Tasks specified in the event.
	 * If the corresponding task doesn't exit, the deletion request will be ignored.
	 * 
	 * @param event the given IronvasDeleteTaskEvent event.
	 */
	private void handleEvent(IronvasDeleteTaskEvent event) {
		if (event == null
				|| event.getTaskInfos() == null || event.getTaskInfos().isEmpty()) {
			LOGGER.info("Got unexpected "
					+ IronvasDeleteTaskEvent.class.getName() + " event. Is null or emtpy.");
			return;
		}

		Map<String, Task> taskList = getTaskList();

		for (IronvasTaskInformation info : event.getTaskInfos()) {
			String taskName = getTaskName(info);
			LOGGER.info("Got an event to delete task: "
					+ taskName);

			Task t = taskList.get(taskName);
			if (t != null) {
				// Sending request two times in a row deletes the task immediately
				LOGGER.info("Deleting task "
						+ t.name() + " (" + t.id() + ")");
				String res = mOmp.deleteTask(t.id())._2();
				LOGGER.info(res);
				res = mOmp.deleteTask(t.id())._2();
				LOGGER.info(res);
			} else {
				LOGGER.info("No task with the name \""
						+ taskName + "\" found.");
			}
		}
	}
	
	/**
	 * Handles a IronvasScanEvent.
	 * Creates an OpenVAS target for the given target if it doesn't exist.
	 * Creates an OpenVAS task for given information.
	 * 
	 * @param event
	 */
	private void handleEvent(IronvasScanEvent event) {
		IronvasTaskInformation info = event.getInfo();
		LOGGER.info("Got an event to scan: "
				+ info.getIP());
		String ip = info.getIP();
		String configName = event.getConfigName();
		Config config = getOpenVASTaskConfig(configName);

		String targetName = getTargetName(event.getInfo());
		String targetID = null;
		Target t = getExistingTarget(targetName);
		if (t == null) {
			targetID = mOmp.createTarget(targetName, ip)._2();
		} else {
			targetID = t.id();
		}

		String taskName = getTaskName(event.getInfo());

		String taskID = mOmp.createTask(taskName, config.id(), targetID)._2();
		String res = mOmp.startTask(taskID)._2();
		LOGGER.info(res);
	}

	/**
	 * Returns a map with all current Tasks directly obtained from
	 * the OpenVAS Server.
	 * 
	 * @return Map<Task Name,Task>
	 */
	private Map<String, Task> getTaskList() {
		Map<String, Task> result = new HashMap<>();

		Seq<Task> taskList = mOmp.getTasks()._2();
		Iterator<Task> taskIterator = taskList.toIterator();
		while (taskIterator.hasNext()) {
			Task t = taskIterator.next();
			result.put(t.name(), t);
		}
		return result;

	}

	/**
	 * Builds the name for the given task information
	 * @param info information about the task
	 * @return the task name that will be used in OpenVAS
	 */
	private String getTaskName(IronvasTaskInformation info) {
		return info.getNamePrefix()
				+ "-" + info.getIP() + "-" + Long.toString(info.getTimestamp());
	}
	
	/**
	 * Builds the name for the given target information
	 * @param info information about the target
	 * @return the target name that will be used in OpenVAS
	 */
	private String getTargetName(IronvasTaskInformation info) {
		return info.getNamePrefix()
				+ "-" + info.getIP();
	}
	
	/**
	 * Tries to obtain a Target with the given name from the OpenVAS server
	 * @param targetname 
	 * @return the target if it exits. Null if no target with the given name exists.
	 */
	private Target getExistingTarget(String targetname) {
		Seq<Target> targetList = mOmp.getTargets()._2();
		Iterator<Target> targetIterator = targetList.toIterator();
		while (targetIterator.hasNext()) {
			Target t = targetIterator.next();
			if (t.name().equals(targetname)) {
				return t;
			}
		}
		return null;
	}

	/**
	 * Return the OpenVAS Configuration for the given name.
	 * If no configuration with this name is found, the default config will be returned.
	 * @param name name of the configuration.
	 * @return The configuration for the given name. If no xonfig with this name exists,  
	 */
	private Config getOpenVASTaskConfig(String name) {
		Config res = mConfigCache.get(name);
		if (res == null) {
			LOGGER.info("The config specified in the Event (\""
					+ name + "\") can't be found on OpenVAS. Using the default config '"
					+ mConfigName + "'.");
			return mDefaultOpenVASTaskConfig;
		}
		return res;
	}

	/**	 * 
	 * - Caches all OpenVAS task configurations
	 * - Checks if the default configuration exists.
	 * - Calls the amqp channel initialization	 * 
	 */
	private void initSubscriber() {
		Seq<Config> configs = mOmp.getConfigs()._2();
		Iterator<Config> configsIterator = configs.toIterator();
		while (configsIterator.hasNext()) {
			Config c = configsIterator.next();
			mConfigCache.put(c.name(), c);
			if (c.name().equals(mConfigName)) {
				mDefaultOpenVASTaskConfig = c;
			}
		}

		if (mDefaultOpenVASTaskConfig == null) {
			LOGGER.warning(String.format("no  default config '%s' found, shutting down the %s...", mConfigName,
					this.getClass().getSimpleName()));
			// We don't start the amqp connection on error.
			return;
		}
		initChannel();
	}
}

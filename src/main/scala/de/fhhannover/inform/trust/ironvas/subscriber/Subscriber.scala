/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.subscriber
 * File:    Subscriber.scala
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

package de.fhhannover.inform.trust.ironvas.subscriber

import java.util.logging.Logger

import scala.collection.JavaConversions.asBuffer
import scala.collection.JavaConversions.asScalaBuffer
import scala.collection.mutable.HashMap
import scala.collection.mutable.Map

import de.fhhannover.inform.trust.ifmapj.binding.IfmapStrings
import de.fhhannover.inform.trust.ifmapj.channel.SSRC
import de.fhhannover.inform.trust.ifmapj.identifier.Identifiers
import de.fhhannover.inform.trust.ifmapj.identifier.IpAddress
import de.fhhannover.inform.trust.ifmapj.messages.Requests
import de.fhhannover.inform.trust.ifmapj.messages.ResultItem
import de.fhhannover.inform.trust.ifmapj.messages.SearchResult
import de.fhhannover.inform.trust.ironvas.omp.OmpConnection
import de.fhhannover.inform.trust.ironvas.omp.Target

/**
 * This subscriber implementation watches the metadata graph for
 * request-for-investigation metadata. If a PDP publishes these metadata
 * on a IP address identifier a new OpenVAS target and task are created.
 * 
 * @author Ralf Steuerwald
 * 
 * @constructor creates a new <code>Subsciber</code>
 * @param omp              this OmpConnection is used to communicate with the
 *                         OpenVAS server
 * @param ssrc             this SSRC is used to communicate with the MAPS
 * @param pdp              the PDP identifier to subscribe for
 * @param targetNamePrefix this prefix is used for the OpenVAS target names
 * @param config           the name of the OpenVAS configuration which will be
 *                         used for new tasks
 */
class Subscriber(
    val omp: OmpConnection, 
    val ssrc: SSRC,
    val pdp: String,
    val targetNamePrefix: String,
    val config: String) extends Runnable {
  
	private val cache = new HashMap[String, Target]
	private val logger = Logger.getLogger(getClass().getName())
	
	/**
	 * The following steps are performed:<br/>
	 * 1. Try to find old targets on the OpenVAS server.
	 * 2. Subscribe for request-for-investigation metadata.
	 * 3. Poll for new metadata.
	 * 4. Create new targets/tasks or delete old ones.
	 * 5. Start at 3 again.
	 */
	override def run() {
		logger.info("starting " + getClass().getSimpleName())

		val (status, currentConfigs) = omp.getConfigs()
		
		if (!currentConfigs.exists {c => c.name == config}) {
			logger.warning("no config '%s' found, subscriber shutting down ...".format(config))
			return
		}
		try {
			searchForExistingTargets()
		  
        	subscribe()
	        while (!Thread.currentThread().isInterrupted()) {
	        	val updates = poll()
	        	
	        	if (updates.getResults().size() > 0) {
	        		val results = asScalaBuffer(updates.getResults())
	        		for (result <- results) {
	        			result.getType() match {
	        			  case SearchResult.Type.searchResult => {
	        				  logger.finer("processing searchResult ...")
	        				  processUpdates(filterSearchResult(result))
	        			  }
	        			  case SearchResult.Type.updateResult => {
	        				  logger.finer("processing updateResult ...")
	        				  processUpdates(filterSearchResult(result))
	        			  }
	        			  case SearchResult.Type.notifyResult => {
	        				  logger.finer("processing notifyResult ...")
	        				  processUpdates(filterSearchResult(result))
	        			  }
	        			  case SearchResult.Type.deleteResult => {
		        			  logger.finer("processing deleteResult ...")
		        			  processDeletes(filterSearchResult(result))
	        			  }
	        			} 
	        		}
	        	}
	        }
        } catch {
            case e: InterruptedException => {
                Thread.currentThread().interrupt();
                logger.info("wakup by interrupt signal, exiting ...")
            }
        }
        finally {
            logger.info("shutdown complete.")
        }
	}
	
	/**
	 * Handle the poll updates.
	 */
	def processUpdates(items: List[ResultItem]) {
		for (item <- items) {
		  val ip = item.getIdentifier() match {
		    case Array(_, i: IpAddress) => i
		    case Array(i: IpAddress, _) => i
		  }

		  if (!cache.contains(ip.getValue())) {
		    logger.info("received new IP address " + ip)
		    
		    val targetName = targetNamePrefix + ip.getValue()
		    val (_, id) = omp.createTarget(targetName, ip.getValue())
		    cache += (ip.getValue() -> Target(id, targetName, ip.getValue()))
		  }
		}
	}
	
	/**
	 * Handle the poll deletes.
	 */
	def processDeletes(items: List[ResultItem]) {
		for (item <- items) {
		  val ip = item.getIdentifier() match {
		    case Array(_, i: IpAddress) => i
		    case Array(i: IpAddress, _) => i
		  }
		  
		  if (cache.contains(ip.getValue())) {
		    logger.info("received delete for IP address " + ip)
		    
		    val target = cache.get(ip.getValue())
		    omp.deleteTarget(target.get.id)
		    
		    cache.remove(ip.getValue())
		  }
		}
	}
	
	/**
	 * Remove all items from the given search result for which the metadata
	 * list is empty.
	 */
	def filterSearchResult(searchResult: SearchResult) = {
	  val predicate = (r: ResultItem) => !r.getMetadata().isEmpty()

	  val scalaBuffer = asBuffer(searchResult.getResultItems())
	  val filtered = scalaBuffer.filter(predicate)
	  
	  filtered.toList
	}
	
	/**
	 * Poll the MAPS for news.
	 */
	def poll() = {
		logger.finer("polling ...")
	  
		val arc = ssrc.getArc()
		val pollResult = arc.poll()
		arc.closeTcpConnection()
		pollResult
	}
	
	/**
	 * Send the subscribe request to the MAPS.
	 */
	def subscribe() {
		logger.finer("subscribing for " + pdp)
		
		val pdpIdentifier = Identifiers.createDev(pdp)
	  
		val subscribeRequest = Requests.createSubscribeReq()
		val subscribeUpdate = Requests.createSubscribeUpdate()
		subscribeUpdate.setName("ironvas-subscriber")
		subscribeUpdate.setMatchLinksFilter("meta:request-for-investigation")
		subscribeUpdate.setMaxDepth(1)
		subscribeUpdate.setStartIdentifier(pdpIdentifier)
		
		subscribeUpdate.addNamespaceDeclaration(
		    IfmapStrings.BASE_PREFIX, IfmapStrings.BASE_NS_URI)
		subscribeUpdate.addNamespaceDeclaration(
		    IfmapStrings.STD_METADATA_PREFIX, IfmapStrings.STD_METADATA_NS_URI)
		
		subscribeRequest.addSubscribeElement(subscribeUpdate)
		
		ssrc.subscribe(subscribeRequest)
	}
	
	/**
	 * Search for existing targets with the ironvas prefix on the OpenVAS server.
	 */
	def searchForExistingTargets() {
		val (status, existingTargets) = omp.getTargets()
		val ironvasTarget = existingTargets.filter(t => t.name.startsWith(targetNamePrefix))
		
		for (target <- ironvasTarget) {
			cache.put(target.hosts, target)
		}
	}

}
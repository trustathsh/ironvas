package de.fhhannover.inform.trust.ironvas.subscriber

import de.fhhannover.inform.trust.ironvas.omp.OmpConnection
import scala.collection.mutable.Set
import scala.collection.mutable.HashSet
import de.fhhannover.inform.trust.ifmapj.channel.SSRC
import de.fhhannover.inform.trust.ifmapj.messages.Request
import de.fhhannover.inform.trust.ifmapj.messages.Requests
import de.fhhannover.inform.trust.ifmapj.binding.IfmapStrings
import de.fhhannover.inform.trust.ifmapj.identifier.Identifiers
import java.util.logging.Logger
import scala.collection.JavaConversions._
import de.fhhannover.inform.trust.ifmapj.messages.SearchResult
import de.fhhannover.inform.trust.ifmapj.messages.ResultItem
import de.fhhannover.inform.trust.ifmapj.identifier.IpAddress
import de.fhhannover.inform.trust.ifmapj.identifier.Identifier

class Subscriber(
    val omp: OmpConnection, 
    val ssrc: SSRC,
    val pdpId: String) extends Runnable {
  
	private val ipCache: Set[Identifier] = new HashSet
	private val logger = Logger.getLogger(getClass().getName())
	
	override def run() {
		logger.info("starting " + getClass().getSimpleName())
        
        try {
        	subscribe()
	        while (!Thread.currentThread().isInterrupted()) {
	        	val updates = poll()
	        	
	        	if (updates.getResults().size() > 0) {
	        		val results = asScalaBuffer(updates.getResults())
	        		for (result <- results) {
	        			result.getType().toString() match {
	        			  case "searchResult" => {
	        				  logger.finer("processing searchResult ...")
	        				  
	        				  processUpdates(filterSearchResult(result))
	        			  }
	        			  case "updateResult" => {
	        				  logger.finer("processing updateResult ...")
	        			    
	        				  processUpdates(filterSearchResult(result))
	        			  }
	        			  case "notifyResult" => {
	        				  logger.finer("processing notifyResult ...")
	        				  
	        				  processUpdates(filterSearchResult(result))
	        			  }
	        			  case "deleteResult" => {
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
	
	def processUpdates(items: List[ResultItem]) = {
		for (item <- items) {
		  val ips = item.getIdentifier().filter {
		    _ match {
		      case ip: IpAddress => true
		      case default => false
		    }
		  }
		  
		  if (ips.length != 1) {
		    throw new RuntimeException("didn't expect more than one IP address")
		  }
		  
		  val ip = ips(0)
		  if (!ipCache.contains(ip)) {
		    logger.info("received new IP address " + ip)
		    
		    // create omp message
		    
		    
		    ipCache += ip
		  }
		}
	}
	
	def processDeletes(items: List[ResultItem]) = {
		for (item <- items) {
		  val ips = item.getIdentifier().filter {
		    _ match {
		      case ip: IpAddress => true
		      case default => false
		    }
		  }
		  
		  if (ips.length != 1) {
		    throw new RuntimeException("didn't expect more than one IP address")
		  }
		  
		  val ip = ips(0)
		  if (ipCache.contains(ip)) {
		    logger.info("received delete for IP address " + ip)
		    
		    // create omp message
		    
		    
		    ipCache.remove(ip)
		  }
		}
	}
	
	
	def filterSearchResult(searchResult: SearchResult) = {
	  val predicate = (r: ResultItem) => !r.getMetadata().isEmpty()

	  val scalaBuffer = asBuffer(searchResult.getResultItems())
	  val filtered = scalaBuffer.filter(predicate)
	  
	  filtered.toList
	}
	
	
	def poll() = {
		logger.finer("polling ...")
	  
		val arc = ssrc.getArc()
		val pollResult = arc.poll()
		arc.closeTcpConnection()
		pollResult
	}
	
	def subscribe() {
		logger.finer("subscribing for " + pdpId)
		
		val pdp = Identifiers.createDev(pdpId)
	  
		val subscribeRequest = Requests.createSubscribeReq(
			Requests.createSubscribeUpdate(
			    "ironvas-subscriber", // name
			    null, // matchLinks // TODO match only on request-for-investigation
			    1, // maxDepth
			    null, // terminal-identifiers
			    null, // maxSize
			    null, // resultFilter
			    pdp) // start-identifier
			 )
		ssrc.subscribe(subscribeRequest)
	}

}
/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas
 * File:    Context.java
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

import java.util.Iterator;
import java.util.List;

import de.fhhannover.inform.trust.ifmapj.binding.IfmapStrings;
import de.fhhannover.inform.trust.ifmapj.channel.SSRC;
import de.fhhannover.inform.trust.ifmapj.exception.IfmapErrorResult;
import de.fhhannover.inform.trust.ifmapj.exception.IfmapException;
import de.fhhannover.inform.trust.ifmapj.identifier.Device;
import de.fhhannover.inform.trust.ifmapj.identifier.Identifiers;
import de.fhhannover.inform.trust.ifmapj.identifier.IpAddress;
import de.fhhannover.inform.trust.ifmapj.messages.Requests;
import de.fhhannover.inform.trust.ifmapj.messages.ResultItem;
import de.fhhannover.inform.trust.ifmapj.messages.SearchRequest;
import de.fhhannover.inform.trust.ifmapj.messages.SearchResult;
import de.fhhannover.inform.trust.ironvas.converter.Converter;

/**
 * The <code>Context</code> provides a collection of informations and objects
 * of the application environment.
 * Components like a {@link Converter} which needs more information for the
 * mapping process can query the <code>Context</code> for the needed
 * information. 
 * 
 * @author Ralf Steuerwald
 *
 */
public class Context {
	
	private SSRC ssrc;
	private String openVasServerId;
	
	public Context(
			SSRC ssrc,
			String openVasServerId) {
		this.ssrc = ssrc;
		this.openVasServerId = openVasServerId;
	}
	
	public String getIfmapPublisherId() {
		return ssrc.getPublisherId();
	}
	
	/**
	 * Searches the MAPS for a device identifier for the given IP address.
	 * 
	 * @param ip the source IP address
	 * @return the device identifier or <code>null</code> if nothing could be
	 *          found
	 */
	public Device getIfmapDeviceForIp(IpAddress ip) {
		SearchRequest req = Requests.createSearchReq();
		req.setMatchLinksFilter("meta:device-ip or meta:access-request-ip or meta:access-request-device");
		req.setMaxDepth(2);
		req.setStartIdentifier(ip);
		
		req.addNamespaceDeclaration(
			    IfmapStrings.BASE_PREFIX, IfmapStrings.BASE_NS_URI);
		req.addNamespaceDeclaration(
			    IfmapStrings.STD_METADATA_PREFIX, IfmapStrings.STD_METADATA_NS_URI);
		
		try {
			SearchResult result = ssrc.search(req);
			if (result.getResultItems().size() >= 3) { // items: device, ip, and device-ip
				Device d = extractDeviceFromResultItems(result.getResultItems());
				return d;
			}
		} catch (IfmapErrorResult e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IfmapException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	
	public String getOpenVasServerId() {
		return openVasServerId;
	}
	
	/**
	 * Pulls the device identifier from the given {@link ResultItem}.
	 * 
	 * @param resultItems the device identifier or <code>null</code>
	 * @return
	 */
	private Device extractDeviceFromResultItems(List<ResultItem> resultItems) {
		for (ResultItem i: resultItems) {
			if (i.getIdentifier1() instanceof Device) {
				return (Device)i.getIdentifier1();
			}
			if (i.getIdentifier2() instanceof Device) {
				return (Device)i.getIdentifier2();
			}
		}
		return null;
	}
	

}

/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.converter
 * File:    FullEventUpdateConverter.java
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

package de.fhhannover.inform.trust.ironvas.converter;

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.w3c.dom.Document;

import de.fhhannover.inform.trust.ifmapj.IfmapJ;
import de.fhhannover.inform.trust.ifmapj.binding.IfmapStrings;
import de.fhhannover.inform.trust.ifmapj.identifier.Identifiers;
import de.fhhannover.inform.trust.ifmapj.identifier.IpAddress;
import de.fhhannover.inform.trust.ifmapj.messages.PublishDelete;
import de.fhhannover.inform.trust.ifmapj.messages.PublishElement;
import de.fhhannover.inform.trust.ifmapj.messages.PublishNotify;
import de.fhhannover.inform.trust.ifmapj.messages.PublishUpdate;
import de.fhhannover.inform.trust.ifmapj.messages.Requests;
import de.fhhannover.inform.trust.ifmapj.metadata.EventType;
import de.fhhannover.inform.trust.ifmapj.metadata.Significance;
import de.fhhannover.inform.trust.ifmapj.metadata.StandardIfmapMetadataFactory;
import de.fhhannover.inform.trust.ironvas.Context;
import de.fhhannover.inform.trust.ironvas.RiskfactorLevel;
import de.fhhannover.inform.trust.ironvas.ThreatLevel;
import de.fhhannover.inform.trust.ironvas.Vulnerability;

/**
 * The <code>FullEventUpdateConverter</code> maps {@link Vulnerability} objects to
 * IF-MAP event metadata and choose the update operation for all
 * vulnerabilities. No filtering is applied to the set of vulnerabilities.
 * 
 * @author Ralf Steuerwald
 *
 */
public class FullEventUpdateConverter implements Converter {
	
	private StandardIfmapMetadataFactory metadataFactory =
			IfmapJ.createStandardMetadataFactory();
	
	private Context context;
	
	private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");

	public PublishElement singleUpdate(Vulnerability v, boolean isNotify) {
		IpAddress ip = Identifiers.createIp4(v.getHost());
		Document metadata = metadataFactory.createEvent(
				v.getNvt().getName(), // name
				dateFormat.format(v.getTimestamp()), // discovered-time
				context.getOpenVasServerId(), // discoverer-id
				(int)((v.getNvt().getCvss_base() * 10)+0.5), // magnitude (0-100)
				0, // confidence TODO define
				mapSignificance(v.getNvt().getRisk_factor()), // significance
				EventType.cve, // type
				v.getId(), // other-type-definition TODO
				v.getDescription(), // information
				v.getNvt().getCve() // vulnerability-uri
				);
		
		if (isNotify) {
			PublishNotify notify = Requests.createPublishNotify();
			notify.setIdentifier1(ip);
			notify.addMetadata(metadata);
			
			return notify;
		}
		else {
			PublishUpdate update = Requests.createPublishUpdate();
			update.setIdentifier1(ip);
			update.addMetadata(metadata);
			
			return update;
		}
	}
	
	public PublishElement singleUpdate(Vulnerability v) {
		return singleUpdate(v, false);
	}
	
	public PublishDelete singleDelete(Vulnerability v) {
		PublishDelete delete = Requests.createPublishDelete();
		
		String filter = String.format(
				"meta:event[@ifmap-publisher-id='%s' "+
				"and other-type-definition='%s']",
				
				context.getIfmapPublisherId(),
				v.getId());
		
		IpAddress ip = Identifiers.createIp4(v.getHost());
//		String filter = String.format(
//				"meta:event[@ifmap-publisher-id='%s' "+
//				"and name='%s' "+
//				"and discovered-time='%s' "+
//				"and discoverer-id='%s' "+
//				"and magnitude='%s' " +
//				"and confidence='0' " +
//				"and significance='%s' " +
//				"and type='%s' "+
//				"and other-type-definition='' " +
//				"and information='%s' "+
//				"and vulnerability-uri='%s']",
//				
//				publisherId,
//				v.getNvt().getName(),
//				dateFormat.format(v.getTimestamp()),
//				openVasServerId,
//				(int)((v.getNvt().getCvss_base() * 10)+0.5),
//				mapSignificance(v.getNvt().getRisk_factor()),
//				EventType.cve,
//				v.getDescription(),
//				v.getNvt().getCve());

		delete.addNamespaceDeclaration("meta", IfmapStrings.STD_METADATA_NS_URI);
		delete.setFilter(filter);
		delete.setIdentifier1(ip);
		
		return delete;
	}

	@Override
	public List<PublishElement> toUpdates(Set<Vulnerability> vulnerabilities) {
		List<PublishElement> result = new ArrayList<PublishElement>();
		for (Vulnerability v : vulnerabilities) {
			result.add(singleUpdate(v));
		}
		return result;
	}
	
	@Override
	public List<PublishElement> toDeletes(Set<Vulnerability> vulnerabilities) {
		List<PublishElement> result = new ArrayList<PublishElement>();
		for (Vulnerability v : vulnerabilities) {
			result.add(singleDelete(v));
		}
		return result;
	}
	
	private Significance mapSignificance(RiskfactorLevel riskFactor) {
		switch (riskFactor) {
		case Critical: return Significance.critical;
		case High:     return Significance.critical;
		case Medium:   return Significance.important;
		case Low:      return Significance.important;
		case None:     return Significance.informational;
		default:       return Significance.informational;
		}
	}
	
	private Significance mapSignificance(ThreatLevel threatLevel) {
		switch (threatLevel) {
		case High:   return Significance.critical;
		case Medium: return Significance.important;
		case Low:    return Significance.important;
		case Log:    return Significance.informational;
		case Debug:  return Significance.informational;
		default:     return Significance.informational;
		}
	}

	@Override
	public Converter setContext(Context context) {
		if (context == null) {
			throw new IllegalArgumentException("context cannot be null");
		}
		this.context = context;
		return this;
	}

}

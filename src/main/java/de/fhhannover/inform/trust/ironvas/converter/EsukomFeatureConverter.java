/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.converter
 * File:    EsukomFeatureConverter.java
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

import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Logger;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import de.fhhannover.inform.trust.ifmapj.channel.SSRC;
import de.fhhannover.inform.trust.ifmapj.identifier.Device;
import de.fhhannover.inform.trust.ifmapj.identifier.Identifiers;
import de.fhhannover.inform.trust.ifmapj.identifier.Identity;
import de.fhhannover.inform.trust.ifmapj.identifier.IdentityType;
import de.fhhannover.inform.trust.ifmapj.identifier.IpAddress;
import de.fhhannover.inform.trust.ifmapj.messages.PublishElement;
import de.fhhannover.inform.trust.ifmapj.messages.PublishUpdate;
import de.fhhannover.inform.trust.ifmapj.messages.Requests;
import de.fhhannover.inform.trust.ironvas.Context;
import de.fhhannover.inform.trust.ironvas.Vulnerability;

/**
 * The <code>EsukomFeatureConverter</code> maps {@link Vulnerability} objects
 * to IF-MAP datastructures defined by the ESUKOM project.
 * No filtering is applied to the set of vulnerabilities.
 * 
 * @author Ralf Steuerwald
 *
 */
public class EsukomFeatureConverter implements Converter {
	
	final static String OTHER_TYPE_DEFINITION = "32939:category";
	final static String NAMESPACE = "http://www.esukom.de/2012/ifmap-metadata/1";
	final static String NAMESPACE_PREFIX = "esukom";
	
	/**
	 * The name for the root category of vulnerability related informations
	 * under a device identifier.
	 */
	final static String ROOT_CATEGORY_NAME = "vulnerability-scan-result";
	
	private static final Logger logger =
			Logger.getLogger(EsukomFeatureConverter.class.getName());
	
	private DocumentBuilderFactory documentBuilderFactory;
	private DocumentBuilder documentBuilder;
	
	private SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
	
	private Context context;
	
	/**
	 * Creates a new {@link EsukomFeatureConverter}. The {@link SSRC} is needed
	 * to enable the Converter to search for {@link Device} identifier by a
	 * IP address.
	 * 
	 * @param publisherId
	 * @param openVasServerId
	 * @param ssrc
	 */
	public EsukomFeatureConverter() {
		documentBuilderFactory = DocumentBuilderFactory.newInstance();

		try {
			documentBuilder = documentBuilderFactory.newDocumentBuilder();
		} catch (ParserConfigurationException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	@Override
	public List<PublishElement> toUpdates(Set<Vulnerability> vulnerabilities) {
		List<PublishElement> elements = new ArrayList<PublishElement>();
		
		// group the vulnerabilities by IP address
		Map<String, List<Vulnerability>> byIp = new HashMap<String, List<Vulnerability>>();
		for (Vulnerability v: vulnerabilities) {
			if (byIp.containsKey(v.getHost())) {
				List<Vulnerability> l = byIp.get(v.getHost());
				l.add(v);
			}
			else {
				List<Vulnerability> l = new ArrayList<Vulnerability>();
				l.add(v);
				byIp.put(v.getHost(), l);
			}
		}
		
		for (List<Vulnerability> vulnerabilityList : byIp.values()) {
			if (vulnerabilityList.size() > 0) {
				// check if there is a device identifier for the current host
				String host = vulnerabilityList.get(0).getHost();
				IpAddress ip = Identifiers.createIp4(host);
				Device dev = context.getIfmapDeviceForIp(ip);
				
				if (dev != null) {
					logger.finer("found device " + dev + " for " + ip);
				}
				else {
					logger.finer("creating device for " + ip);
					dev = Identifiers.createDev(new SecureRandom().nextInt() + "");
				}
				
				// create the "vulnerability-scan-result" root category
				PublishUpdate update = Requests.createPublishUpdate();
				Identity category = createCategory(ROOT_CATEGORY_NAME, dev.getName());
				Document deviceCategory = createCategoryLink("device-category");
				update.setIdentifier1(dev);
				update.setIdentifier2(category);
				update.addMetadata(deviceCategory);
				elements.add(update);
				
				// create sub-tree for each of the vulnerabilities
				for (Vulnerability v : vulnerabilities) {
					List<PublishElement> e = singleVulnerability(v, category, dev);
					elements.addAll(e);
				}
			}
		}
		return elements;
	}
	
	/**
	 * Create the sub-tree for the given {@link Vulnerability} under the parent
	 * category node.
	 * 
	 * @param v              the {@link Vulnerability} to process
	 * @param parentCategory the parent node of the {@link Vulnerability}
	 *                        category node
	 * @param dev            the device which is affected by the vulnerability
	 * @return a list of {@link PublishElement}s containing the publish
	 *          information for the sub-tree
	 */
	private List<PublishElement> singleVulnerability(Vulnerability v, Identity parentCategory, Device dev) {
		List<PublishElement> elements = new ArrayList<PublishElement>();
		
		// create a new (vulnerability) category for the vulnerability
		PublishUpdate vulnerabilityUpdate = Requests.createPublishUpdate();
		Identity vulnerabilityCategory = createCategory(
				parentCategory.getName() + ".vulnerability:" + v.getId(), dev.getName());
		Document categoryLink = createCategoryLink("subcategory-of");
		vulnerabilityUpdate.setIdentifier1(parentCategory);
		vulnerabilityUpdate.setIdentifier2(vulnerabilityCategory);
		vulnerabilityUpdate.addMetadata(categoryLink);
		elements.add(vulnerabilityUpdate);

		// create the features
		Document[] features = new Document[] {
				createFeature("Name", "qualified", v.getNvt().getName(), v),
				createFeature("Port", "qualified", v.getPort(), v),
				createFeature("Cvss-base", "quantitive", v.getNvt().getCvss_base() + "", v),
				createFeature("Threat", "quantitive", v.getNvt().getRisk_factor().toString(), v),
				createFeature("Description", "arbitrary", v.getDescription(), v),
				createFeature("CVE", "qualified", v.getNvt().getCve(), v), // TODO split "multi CVE"
		};
		for (Document d : features) {
			PublishUpdate u = Requests.createPublishUpdate();
			u.setIdentifier1(vulnerabilityCategory);
			u.addMetadata(d);
			elements.add(u);
		}
		return elements;
	}
	
	/**
	 * Creates a identity-category node.
	 * 
	 * @param name the name of the category
	 * @param admDomain the device name
	 * @return
	 */
	private Identity createCategory(String name, String admDomain) {
		return Identifiers.createIdentity(
				IdentityType.other,
				name,
				admDomain,
				OTHER_TYPE_DEFINITION);
	}
	
	/**
	 * Creates a feature document from the given informations.
	 * 
	 * @param id
	 * @param type
	 * @param value
	 * @param v
	 * @return
	 */
	private Document createFeature(String id, String type, String value, Vulnerability v) {
		Document doc = documentBuilder.newDocument();
		Element feature = doc.createElementNS(NAMESPACE, NAMESPACE_PREFIX + ":feature");
		
		feature.setAttributeNS(null, "ifmap-cardinality", "multiValue");
		feature.setAttribute("ctxp-timestamp", dateFormat.format(v.getTimestamp()));

		Element idElement = doc.createElement("id");
		idElement.setTextContent(id);
		feature.appendChild(idElement);
		
		Element typeElement = doc.createElement("type");
		typeElement.setTextContent(type);
		feature.appendChild(typeElement);
		
		Element valueElement = doc.createElement("value");
		valueElement.setTextContent(value);
		feature.appendChild(valueElement);
		
		doc.appendChild(feature);
		return doc;
	}
	
	private Document createCategoryLink(String name) {
		Document doc = documentBuilder.newDocument();
		Element e = doc.createElementNS(NAMESPACE, NAMESPACE_PREFIX + ":" + name);
		e.setAttributeNS(null, "ifmap-cardinality", "singleValue");
		
		doc.appendChild(e);
		return doc;
	}

	@Override
	public List<PublishElement> toDeletes(Set<Vulnerability> vulnerabilities) {
		// TODO Auto-generated method stub
		return null;
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

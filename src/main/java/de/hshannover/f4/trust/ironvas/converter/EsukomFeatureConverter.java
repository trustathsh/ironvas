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
package de.hshannover.f4.trust.ironvas.converter;

import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
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

import de.hshannover.f4.trust.ifmapj.identifier.Device;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ifmapj.identifier.Identity;
import de.hshannover.f4.trust.ifmapj.identifier.IdentityType;
import de.hshannover.f4.trust.ifmapj.identifier.IpAddress;
import de.hshannover.f4.trust.ifmapj.messages.PublishDelete;
import de.hshannover.f4.trust.ifmapj.messages.PublishElement;
import de.hshannover.f4.trust.ifmapj.messages.PublishUpdate;
import de.hshannover.f4.trust.ifmapj.messages.Requests;
import de.hshannover.f4.trust.ironvas.Context;
import de.hshannover.f4.trust.ironvas.Vulnerability;

/**
 * The <code>EsukomFeatureConverter</code> maps {@link Vulnerability} objects to
 * IF-MAP datastructures defined by the ESUKOM project. No filtering is applied
 * to the set of vulnerabilities.
 *
 * @author Ralf Steuerwald
 *
 */
public class EsukomFeatureConverter implements Converter {

	static final String OTHER_TYPE_DEFINITION = "32939:category";
	static final String NAMESPACE = "http://www.esukom.de/2012/ifmap-metadata/1";
	static final String NAMESPACE_PREFIX = "esukom";

    /**
     * The name for the root category of vulnerability related informations
     * under a device identifier.
     */
	static final String ROOT_CATEGORY_NAME = "vulnerability-scan-result";

    private static final Logger LOGGER = Logger
            .getLogger(EsukomFeatureConverter.class.getName());

    private DocumentBuilderFactory mDocumentBuilderFactory;
    private DocumentBuilder mDocumentBuilder;

    private SimpleDateFormat mDateFormat = new SimpleDateFormat(
            "yyyy-MM-dd'T'HH:mm:ss");

    private Context mContext;

    private Map<String, Device> mHostDeviceMaping = new HashMap<String, Device>();

    /**
     * Creates a new {@link EsukomFeatureConverter}. The {@link SSRC} is needed
     * to enable the Converter to search for {@link Device} identifier by a IP
     * address.
     *
     * @param publisherId
     * @param openVasServerId
     * @param ssrc
     */
    public EsukomFeatureConverter() {
        mDocumentBuilderFactory = DocumentBuilderFactory.newInstance();

        try {
            mDocumentBuilder = mDocumentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public List<PublishElement> toUpdates(Set<Vulnerability> vulnerabilities) {
        List<PublishElement> elements = new ArrayList<PublishElement>();

        // group the vulnerabilities by IP address
        Map<String, List<Vulnerability>> byIp = sortByIp(vulnerabilities);

        for (List<Vulnerability> vulnerabilityList : byIp.values()) {
            if (vulnerabilityList.size() > 0) {
                // check if there is a device identifier for the current host
                Vulnerability first = vulnerabilityList.get(0);
                Device dev = findDeviceForVulnerability(first);

                if (dev != null) {
                    LOGGER.finer("found device " + dev + " for "
                            + first.getHost());
                } else {
                    LOGGER.finer("creating device for " + first.getHost());
                    dev = Identifiers.createDev(new SecureRandom().nextInt()
                            + "");
                }
                mHostDeviceMaping.put(first.getHost(), dev);

                // create the "vulnerability-scan-result" root category
                // for the current host
                PublishUpdate update = Requests.createPublishUpdate();
                Identity category = createCategory(ROOT_CATEGORY_NAME,
                        dev.getName());
                Document deviceCategory = createCategoryLink("device-category");
                update.setIdentifier1(dev);
                update.setIdentifier2(category);
                update.addMetadata(deviceCategory);
                elements.add(update);

                // create sub-tree for each of the vulnerabilities
                for (Vulnerability v : vulnerabilities) {
                    List<PublishElement> e = singleVulnerability(v, category,
                            dev);
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
     * @param v
     *            the {@link Vulnerability} to process
     * @param parentCategory
     *            the parent node of the {@link Vulnerability} category node
     * @param dev
     *            the device which is affected by the vulnerability
     * @return a list of {@link PublishElement}s containing the publish
     *         information for the sub-tree
     */
    private List<PublishElement> singleVulnerability(Vulnerability v,
            Identity parentCategory, Device dev) {
        List<PublishElement> elements = new ArrayList<PublishElement>();

        // create a new (vulnerability) category for the vulnerability
        PublishUpdate vulnerabilityUpdate = Requests.createPublishUpdate();
        Identity vulnerabilityCategory = createCategory(
                parentCategory.getName() + ".vulnerability:" + v.getId(),
                dev.getName());
        Document categoryLink = createCategoryLink("subcategory-of");
        vulnerabilityUpdate.setIdentifier1(parentCategory);
        vulnerabilityUpdate.setIdentifier2(vulnerabilityCategory);
        vulnerabilityUpdate.addMetadata(categoryLink);
        elements.add(vulnerabilityUpdate);

        // create the features
        Document[] features = new Document[] {
                createFeature("Name", "qualified", v.getNvt().getName(), v),
                createFeature("Port", "qualified", v.getPort(), v),
                createFeature("Cvss-base", "quantitive", v.getNvt()
                        .getCvssBase() + "", v),
                createFeature("Threat", "quantitive", v.getNvt()
                        .getRiskFactor().toString(), v),
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
     * @param name
     *            the name of the category
     * @param admDomain
     *            the device name
     * @return
     */
    private Identity createCategory(String name, String admDomain) {
        return Identifiers.createIdentity(IdentityType.other, name, admDomain,
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
    private Document createFeature(String id, String type, String value,
            Vulnerability v) {
        Document doc = mDocumentBuilder.newDocument();
        Element feature = doc.createElementNS(NAMESPACE, NAMESPACE_PREFIX
                + ":feature");

        feature.setAttributeNS(null, "ifmap-cardinality", "multiValue");
        feature.setAttribute("ctxp-timestamp",
//                dateFormat.format(v.getTimestamp()));
        		mDateFormat.format(new Date()));

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
        Document doc = mDocumentBuilder.newDocument();
        Element e = doc.createElementNS(NAMESPACE, NAMESPACE_PREFIX + ":"
                + name);
        e.setAttributeNS(null, "ifmap-cardinality", "singleValue");

        doc.appendChild(e);
        return doc;
    }

    @Override
    public List<PublishElement> toDeletes(Set<Vulnerability> vulnerabilities) {
        List<PublishElement> elements = new ArrayList<PublishElement>();

        Map<String, List<Vulnerability>> byIp = sortByIp(vulnerabilities);

        for (List<Vulnerability> vulnerabilityList : byIp.values()) {
            if (vulnerabilityList.size() > 0) {
                Vulnerability first = vulnerabilityList.get(0);
                Device dev = mHostDeviceMaping.get(first.getHost());

                for (Vulnerability v : vulnerabilityList) {
                    List<PublishElement> e = singleVulnerabilityDelete(v, dev);
                    elements.addAll(e);
                }
            }
        }
        return elements;
    }

    private List<PublishElement> singleVulnerabilityDelete(Vulnerability v,
            Device dev) {
        List<PublishElement> elements = new ArrayList<PublishElement>();

        // delete link to parent category (vulnerability-scan-result)
        PublishDelete parentDelete = Requests.createPublishDelete();
        Identity parentCategory = createCategory(ROOT_CATEGORY_NAME,
                dev.getName());
        Identity vulnerability = createCategory(parentCategory.getName()
                + ".vulnerability:" + v.getId(), dev.getName());
        parentDelete.setIdentifier1(parentCategory);
        parentDelete.setIdentifier2(vulnerability);
        String filter = String.format(
                "%s:subcategory-of[@ifmap-publisher-id='%s']",
                NAMESPACE_PREFIX, mContext.getIfmapPublisherId());
        parentDelete.setFilter(filter);
        parentDelete.addNamespaceDeclaration(NAMESPACE_PREFIX, NAMESPACE);

        elements.add(parentDelete);

        // delete all metadata (=features) from the vulnerability(-category)
        PublishDelete featureDelete = Requests.createPublishDelete();
        featureDelete.setIdentifier1(vulnerability);
        String featureFilter = String.format(
                "%s:feature[@ifmap-publisher-id='%s']", NAMESPACE_PREFIX,
                mContext.getIfmapPublisherId());
        featureDelete.setFilter(featureFilter);
        featureDelete.addNamespaceDeclaration(NAMESPACE_PREFIX, NAMESPACE);
        elements.add(featureDelete);

        return elements;
    }

    @Override
    public Converter setContext(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context cannot be null");
        }
        this.mContext = context;
        return this;
    }

    private Map<String, List<Vulnerability>> sortByIp(
            Set<Vulnerability> vulnerabilities) {
        Map<String, List<Vulnerability>> byIp = new HashMap<String, List<Vulnerability>>();
        for (Vulnerability v : vulnerabilities) {
            if (!byIp.containsKey(v.getHost())) {
                List<Vulnerability> l = new ArrayList<Vulnerability>();
                byIp.put(v.getHost(), l);
            }
            List<Vulnerability> l = byIp.get(v.getHost());
            l.add(v);
        }
        return byIp;
    }

    private Device findDeviceForVulnerability(Vulnerability v) {
        String host = v.getHost();
        IpAddress ip = Identifiers.createIp4(host);
        Device dev = mContext.getIfmapDeviceForIp(ip);

        return dev;
    }

}

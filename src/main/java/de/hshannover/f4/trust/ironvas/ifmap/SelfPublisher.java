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
 * This file is part of ironvas, version 0.1.6, implemented by the Trust@HsH
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

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;

import de.hshannover.f4.trust.ifmapj.exception.MarshalException;
import de.hshannover.f4.trust.ifmapj.identifier.Identifier;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ifmapj.messages.MetadataLifetime;
import de.hshannover.f4.trust.ifmapj.messages.PublishElement;
import de.hshannover.f4.trust.ifmapj.messages.PublishRequest;
import de.hshannover.f4.trust.ifmapj.messages.PublishUpdate;
import de.hshannover.f4.trust.ifmapj.messages.Requests;
import de.hshannover.f4.trust.ifmapj.metadata.StandardIfmapMetadataFactory;
import de.hshannover.f4.trust.ifmapj.metadata.StandardIfmapMetadataFactoryImpl;
import de.hshannover.f4.trust.ifmapj.metadata.VendorSpecificMetadataFactory;
import de.hshannover.f4.trust.ifmapj.metadata.VendorSpecificMetadataFactoryImpl;

public class SelfPublisher {

	private static final String SIMU_METADATA_PREFIX = "simu";
	private static final String SIMU_METADATA_URI = "http://simu-project.de/XMLSchema/1";

	private static final String SIMU_IDENTIFIER_PREFIX = "simu";
	private static final String SIMU_IDENTIFIER_URI = "http://simu-project.de/XMLSchema/1";

	private static final StandardIfmapMetadataFactory FACTORY = new StandardIfmapMetadataFactoryImpl();
	private static final VendorSpecificMetadataFactory VENDOR_FACTORY = new VendorSpecificMetadataFactoryImpl();

	public static PublishRequest createSelfPublishRequest(String ipValue, String macValue, String deviceName,
			String serviceName, String serviceType, String servicePort, String implementationName,
			String implementationVersion, String implementationPlatform, String implementationPatch,
			String administrativeDomain) {
		List<PublishElement> publishElements = new ArrayList<PublishElement>();

		Identifier ip = Identifiers.createIp4(ipValue);
		if (macValue != null) {
			Identifier mac = Identifiers.createMac(macValue);
			publishElements.add(createIpMacPubElement(ip, mac));
		}
		Identifier device = Identifiers.createDev(deviceName);
		publishElements.add(createDeviceIpPubElement(device, ip));

		try {
			Identifier service = createService(serviceName, serviceType, servicePort, administrativeDomain);
			Identifier implementation = createImplementation(implementationName, implementationVersion,
					implementationPlatform, implementationPatch);

			publishElements.add(createServiceIpPubElement(service, ip));
			publishElements.add(createServiceImplementationPubElement(service, implementation));
		} catch (MarshalException e) {
			e.printStackTrace();
		}

		return Requests.createPublishReq(publishElements);
	}

	private static Identifier createImplementation(String implementationName, String implementationVersion,
			String implementationPatch, String implementationPlatform)
					throws MarshalException {
		StringBuilder implementationDocument = new StringBuilder();
		implementationDocument.append("<"
				+ SIMU_IDENTIFIER_PREFIX + ":implementation ");
		implementationDocument.append("xmlns:"
				+ SIMU_IDENTIFIER_PREFIX + "=\"" + SIMU_IDENTIFIER_URI + "\" ");
		implementationDocument.append("name=\""
				+ implementationName + "\" ");
		implementationDocument.append("version=\""
				+ implementationVersion + "\" ");
		implementationDocument.append("local-version=\""
				+ implementationPatch + "\" ");
		implementationDocument.append("platform=\""
				+ implementationPlatform + "\" ");
		implementationDocument.append(">");
		implementationDocument.append("</"
				+ SIMU_IDENTIFIER_PREFIX + ":implementation>");

		return Identifiers.createExtendedIdentity(implementationDocument.toString());
	}

	private static Identifier createService(String serviceName, String serviceType, String servicePort,
			String administrativeDomain) throws MarshalException {
		StringBuilder serviceDocument = new StringBuilder();
		serviceDocument.append("<"
				+ SIMU_IDENTIFIER_PREFIX + ":service ");
		serviceDocument.append("administrative-domain=\""
				+ administrativeDomain + "\" ");
		serviceDocument.append("xmlns:"
				+ SIMU_IDENTIFIER_PREFIX + "=\"" + SIMU_IDENTIFIER_URI + "\" ");
		serviceDocument.append("type=\""
				+ serviceType + "\" ");
		serviceDocument.append("name=\""
				+ serviceName + "\" ");
		serviceDocument.append("port=\""
				+ servicePort + "\" ");
		serviceDocument.append(">");
		serviceDocument.append("</"
				+ SIMU_IDENTIFIER_PREFIX + ":service>");

		return Identifiers.createExtendedIdentity(serviceDocument.toString());
	}

	private static PublishElement createServiceImplementationPubElement(Identifier service, Identifier implementation) {
		PublishUpdate result = Requests.createPublishUpdate();
		String xmlString = "<"
				+ SIMU_METADATA_PREFIX + ":service-implementation "
				+ "ifmap-cardinality=\"singleValue\" "
				+ "xmlns:" + SIMU_METADATA_PREFIX + "=\"" + SIMU_METADATA_URI + "\">"
				+ "</" + SIMU_METADATA_PREFIX + ":service-implementation>";
		Document link = VENDOR_FACTORY.createMetadata(xmlString);

		result.setIdentifier1(service);
		result.setIdentifier2(implementation);
		result.addMetadata(link);
		result.setLifeTime(MetadataLifetime.session);

		return result;
	}

	private static PublishElement createServiceIpPubElement(Identifier service, Identifier ip) {
		PublishUpdate result = Requests.createPublishUpdate();
		String xmlString = "<"
				+ SIMU_METADATA_PREFIX + ":service-ip "
				+ "ifmap-cardinality=\"singleValue\" "
				+ "xmlns:" + SIMU_METADATA_PREFIX + "=\"" + SIMU_METADATA_URI + "\">"
				+ "</" + SIMU_METADATA_PREFIX + ":service-ip>";
		Document link = VENDOR_FACTORY.createMetadata(xmlString);

		result.setIdentifier1(service);
		result.setIdentifier2(ip);
		result.addMetadata(link);
		result.setLifeTime(MetadataLifetime.session);

		return result;
	}

	private static PublishElement createDeviceIpPubElement(Identifier device, Identifier ip) {
		PublishUpdate result = Requests.createPublishUpdate();
		Document link = FACTORY.createDevIp();

		result.setIdentifier1(device);
		result.setIdentifier2(ip);
		result.addMetadata(link);
		result.setLifeTime(MetadataLifetime.session);

		return result;
	}

	private static PublishElement createIpMacPubElement(Identifier ip, Identifier mac) {
		PublishUpdate result = Requests.createPublishUpdate();
		Document link = FACTORY.createIpMac();

		result.setIdentifier1(ip);
		result.setIdentifier2(mac);
		result.addMetadata(link);
		result.setLifeTime(MetadataLifetime.session);

		return result;
	}

}

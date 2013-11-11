package de.fhhannover.inform.trust.ironvas.converter;

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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;

import de.fhhannover.inform.trust.ifmapj.identifier.IpAddress;
import de.fhhannover.inform.trust.ifmapj.messages.PublishDelete;
import de.fhhannover.inform.trust.ifmapj.messages.PublishUpdate;
import de.fhhannover.inform.trust.ironvas.Context;
import de.fhhannover.inform.trust.ironvas.Nvt;
import de.fhhannover.inform.trust.ironvas.RiskfactorLevel;
import de.fhhannover.inform.trust.ironvas.ThreatLevel;
import de.fhhannover.inform.trust.ironvas.Vulnerability;
import static org.junit.Assert.*;

import static org.mockito.Mockito.*;

public class EventUpdateConverterTest {

	private EventUpdateConverter converter;
	private SimpleDateFormat format;
	private Nvt nvt;
	private Vulnerability v;
	private Date date;


	@Before
	public void setUp() {
		String publisherId = "ironvas";
		String openVasServerId = "openvas@example.test";

		converter = new EventUpdateConverter();
		Context context = mock(Context.class);
		when(context.getIfmapPublisherId()).thenReturn(publisherId);
		when(context.getOpenVasServerId()).thenReturn(openVasServerId);
		converter.setContext(context);

		format = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.GERMANY);

		String nvt_oid = "1.3.6.1.4.1.25623.1.0.11229";
		String nvt_name = "phpinfo.php";
		float nvt_cvss_base = 0.0f;
		RiskfactorLevel riskfactor = RiskfactorLevel.Low;
		String cve = "NOCVE";
		String bid = "NOBID";

		String id = "f75673cf-c32a-467b-b495-1eb5fb2de100";
		date = new Date(0);
		String subnet = "192.168.7.7";
		String host = "192.168.7.7";
		String port = "http (80/tcp)";
		ThreatLevel threat = ThreatLevel.Medium;
		String description = "";

		nvt = new Nvt(nvt_oid, nvt_name, nvt_cvss_base, riskfactor, cve, bid);
		v = new Vulnerability(id, date, subnet, host, port, threat, description, nvt);
	}

	@Test
	public void testSingleUpdateMetadataSize() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		assertEquals(1, u.getMetadata().size());
	}

	@Test
	public void testSingleUpdateName() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		assertEquals("phpinfo.php",
				d.getElementsByTagName("name").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateDiscoveredTime() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		assertEquals(format.format(date),
				d.getElementsByTagName("discovered-time").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateDiscovererId() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		assertEquals("openvas@example.test",
				d.getElementsByTagName("discoverer-id").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateMagnitude() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		assertEquals("0",
				d.getElementsByTagName("magnitude").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateConfidence() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		assertEquals("0",
				d.getElementsByTagName("confidence").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateSignificance() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		assertEquals("important",
				d.getElementsByTagName("significance").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateType() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		assertEquals("cve",
				d.getElementsByTagName("type").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateOtherTypeDefinition() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		assertEquals("f75673cf-c32a-467b-b495-1eb5fb2de100",
				d.getElementsByTagName("other-type-definition").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateInformation() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		assertEquals("",
				d.getElementsByTagName("information").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateVulnerabilityUri() {
		PublishUpdate u = (PublishUpdate)converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		assertEquals("NOCVE",
				d.getElementsByTagName("vulnerability-uri").item(0).getTextContent());
	}

	@Test
	public void testSingleDeleteIpAddress() {
		PublishDelete d = converter.singleDelete(v);
		assertEquals("192.168.7.7", ((IpAddress)d.getIdentifier1()).getValue());
	}

	@Test
	public void testSingleDeleteFilter() {
		PublishDelete d = converter.singleDelete(v);
		String filter = "meta:event[@ifmap-publisher-id='ironvas' "+
				"and other-type-definition='f75673cf-c32a-467b-b495-1eb5fb2de100']";
		assertEquals(filter, d.getFilter());
	}
}

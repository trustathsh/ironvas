/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.converter
 * File:    FullEventUpdateConverterTest.java
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
import java.util.Date;
import java.util.Locale;

import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;

import de.fhhannover.inform.trust.ifmapj.identifier.IpAddress;
import de.fhhannover.inform.trust.ifmapj.messages.PublishDelete;
import de.fhhannover.inform.trust.ifmapj.messages.PublishUpdate;
import de.fhhannover.inform.trust.ironvas.Nvt;
import de.fhhannover.inform.trust.ironvas.RiskfactorLevel;
import de.fhhannover.inform.trust.ironvas.ThreatLevel;
import de.fhhannover.inform.trust.ironvas.Vulnerability;
import static org.junit.Assert.*;

public class FullEventUpdateConverterTest {
	
	private FullEventUpdateConverter converter;
	private SimpleDateFormat format;
	private Nvt nvt;
	private Vulnerability v;
	private Date date;
	
	
	@Before
	public void setUp() {
		String publisherId = "ironvas";
		String openVASId = "openvas@example.test";
		converter = new FullEventUpdateConverter(publisherId, openVASId);
		
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

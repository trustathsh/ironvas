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
package de.hshannover.f4.trust.ironvas.converter;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;

import de.hshannover.f4.trust.ifmapj.identifier.IpAddress;
import de.hshannover.f4.trust.ifmapj.messages.PublishDelete;
import de.hshannover.f4.trust.ifmapj.messages.PublishUpdate;
import de.hshannover.f4.trust.ironvas.Context;
import de.hshannover.f4.trust.ironvas.Nvt;
import de.hshannover.f4.trust.ironvas.RiskfactorLevel;
import de.hshannover.f4.trust.ironvas.ThreatLevel;
import de.hshannover.f4.trust.ironvas.Vulnerability;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class EventUpdateConverterTest {

	private EventUpdateConverter mConverter;
	private SimpleDateFormat mFormat;
	private Nvt mNvt;
	private Vulnerability mV;
	private Date mDate;


	@Before
	public void setUp() {
		String publisherId = "ironvas";
		String openVasServerId = "openvas@example.test";

		mConverter = new EventUpdateConverter();
		Context context = mock(Context.class);
		when(context.getIfmapPublisherId()).thenReturn(publisherId);
		when(context.getOpenVasServerId()).thenReturn(openVasServerId);
		mConverter.setContext(context);

		mFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ", Locale.GERMANY);

		String nvtOid = "1.3.6.1.4.1.25623.1.0.11229";
		String nvtName = "phpinfo.php";
		float nvtCvssBase = 0.0f;
		RiskfactorLevel riskfactor = RiskfactorLevel.Low;
		String cve = "NOCVE";
		String bid = "NOBID";

		String id = "f75673cf-c32a-467b-b495-1eb5fb2de100";
		mDate = new Date(0);
		String subnet = "192.168.7.7";
		String host = "192.168.7.7";
		String port = "http (80/tcp)";
		ThreatLevel threat = ThreatLevel.Medium;
		String description = "";

		mNvt = new Nvt(nvtOid, nvtName, nvtCvssBase, riskfactor, cve, bid);
		mV = new Vulnerability(id, mDate, subnet, host, port, threat, description, mNvt);
	}

	@Test
	public void testSingleUpdateMetadataSize() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		assertEquals(1, u.getMetadata().size());
	}

	@Test
	public void testSingleUpdateName() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		Document d = u.getMetadata().get(0);
		assertEquals("phpinfo.php",
				d.getElementsByTagName("name").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateDiscoveredTime() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		Document d = u.getMetadata().get(0);
		assertEquals(mFormat.format(mDate),
				d.getElementsByTagName("discovered-time").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateDiscovererId() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		Document d = u.getMetadata().get(0);
		assertEquals("openvas@example.test",
				d.getElementsByTagName("discoverer-id").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateMagnitude() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		Document d = u.getMetadata().get(0);
		assertEquals("0",
				d.getElementsByTagName("magnitude").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateConfidence() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		Document d = u.getMetadata().get(0);
		assertEquals("0",
				d.getElementsByTagName("confidence").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateSignificance() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		Document d = u.getMetadata().get(0);
		assertEquals("important",
				d.getElementsByTagName("significance").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateType() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		Document d = u.getMetadata().get(0);
		assertEquals("cve",
				d.getElementsByTagName("type").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateOtherTypeDefinition() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		Document d = u.getMetadata().get(0);
		assertEquals("f75673cf-c32a-467b-b495-1eb5fb2de100",
				d.getElementsByTagName("other-type-definition").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateInformation() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		Document d = u.getMetadata().get(0);
		assertEquals("",
				d.getElementsByTagName("information").item(0).getTextContent());
	}

	@Test
	public void testSingleUpdateVulnerabilityUri() {
		PublishUpdate u = (PublishUpdate) mConverter.singleUpdate(mV);
		Document d = u.getMetadata().get(0);
		assertEquals("NOCVE",
				d.getElementsByTagName("vulnerability-uri").item(0).getTextContent());
	}

	@Test
	public void testSingleDeleteIpAddress() {
		PublishDelete d = mConverter.singleDelete(mV);
		assertEquals("192.168.7.7", ((IpAddress) d.getIdentifier1()).getValue());
	}

	@Test
	public void testSingleDeleteFilter() {
		PublishDelete d = mConverter.singleDelete(mV);
		String filter = "meta:event[@ifmap-publisher-id='ironvas' "
				+ "and other-type-definition='f75673cf-c32a-467b-b495-1eb5fb2de100']";
		assertEquals(filter, d.getFilter());
	}
}

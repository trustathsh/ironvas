package de.fhhannover.inform.trust.ironvas.converter;

import java.text.SimpleDateFormat;
import java.util.Date;

import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;

import de.fhhannover.inform.trust.ifmapj.messages.PublishUpdate;
import de.fhhannover.inform.trust.ironvas.Nvt;
import de.fhhannover.inform.trust.ironvas.RiskfactorLevel;
import de.fhhannover.inform.trust.ironvas.ThreatLevel;
import de.fhhannover.inform.trust.ironvas.Vulnerability;
import static org.junit.Assert.*;

public class FullEventUpdateConverterTest {
	
	private static final String PUBLISHER_ID = "ironvas";
	private static final String OPENVAS_SERVER_ID = "openvas@example.test";
	
	private FullEventUpdateConverter converter;
	
	
	@Before
	public void setUp() {
		converter = new FullEventUpdateConverter(PUBLISHER_ID, OPENVAS_SERVER_ID);
	}
	
	@Test
	public void testSingleUpdate() {
		SimpleDateFormat format =
				new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssZ");
		
		String nvt_oid = "1.3.6.1.4.1.25623.1.0.11229";
		String nvt_name = "phpinfo.php";
		float nvt_cvss_base = 0.0f;
		RiskfactorLevel riskfactor = RiskfactorLevel.Low;
		String cve = "NOCVE";
		String bid = "NOBID";
		
		String id = "f75673cf-c32a-467b-b495-1eb5fb2de100";
		Date date = new Date();
		String subnet = "192.168.7.7";
		String host = "192.168.7.7";
		String port = "http (80/tcp)";
		ThreatLevel threat = ThreatLevel.Medium;
		String description = "";
		
		Nvt nvt = new Nvt(nvt_oid, nvt_name, nvt_cvss_base, riskfactor, cve, bid);
		Vulnerability v = new Vulnerability(id, date, subnet, host, port, threat, description, nvt);
		
		PublishUpdate u = converter.singleUpdate(v);
		Document d = u.getMetadata().get(0);
		
		assertEquals(1, u.getMetadata().size());
		assertEquals(nvt_name,
				d.getElementsByTagName("name").item(0).getTextContent());
		assertEquals(format.format(date),
				d.getElementsByTagName("discovered-time").item(0).getTextContent());
		assertEquals(OPENVAS_SERVER_ID,
				d.getElementsByTagName("discoverer-id").item(0).getTextContent());
		assertEquals("0",
				d.getElementsByTagName("magnitude").item(0).getTextContent());
		assertEquals("0",
				d.getElementsByTagName("confidence").item(0).getTextContent());
		assertEquals("important",
				d.getElementsByTagName("significance").item(0).getTextContent());
		assertEquals("cve",
				d.getElementsByTagName("type").item(0).getTextContent());
		assertEquals("",
				d.getElementsByTagName("other-type-definition").item(0).getTextContent());
		assertEquals(description,
				d.getElementsByTagName("information").item(0).getTextContent());
		assertEquals(cve,
				d.getElementsByTagName("vulnerability-uri").item(0).getTextContent());
		
		
	}
}

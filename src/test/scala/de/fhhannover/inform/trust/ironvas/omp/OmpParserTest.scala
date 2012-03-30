/*
 * Project: ironvas
 * Package: test.scala.de.fhhannover.inform.trust.ironvas.omp
 * File:    OmpParserTest.scala
 *
 * Copyright (C) 2011-2012 Fachhochschule Hannover
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

package de.fhhannover.inform.trust.ironvas.omp

import org.junit.Assert._
import org.junit.Test
import org.junit.Before
import java.util.Calendar
import org.junit.Ignore

class OmpParserTest {

    val datesOk = Map(
            "Thu Apr 7 16:28:52 2011"  -> (3, 7,  16, 28, 52, 2011),
            "Tue Aug 25 21:48:25 2009" -> (7, 25, 21, 48, 25, 2009),
            "Wed Jun 30 21:49:08 1993" -> (5, 30, 21, 49, 8, 1993),
            "Wed Mar  7 21:27:59 2012" -> (2, 7,  21, 27, 59, 2012)
            )
    
    var parser: OmpParser = _
        
    @Before
    def setUp() {
        parser = new OmpParser
    }
        
    @Test
    def testParseDate() {
        for (item <- datesOk) {
            item match {
                case (dateString, (month, day, hour, minute, second, year)) => {
                    val date = parser.parseDate(dateString)
                    val cal = Calendar.getInstance()
                    cal.setTime(date)
                    
                    assertEquals(cal.get(Calendar.MONTH), month)
                    assertEquals(cal.get(Calendar.DAY_OF_MONTH), day)
                    assertEquals(cal.get(Calendar.HOUR_OF_DAY), hour)
                    assertEquals(cal.get(Calendar.MINUTE), minute)
                    assertEquals(cal.get(Calendar.SECOND), second)
                    assertEquals(cal.get(Calendar.YEAR), year)
                }
            }
        }
    }

    @Test
    def testParseDateEquals() {
        val date1 = parser.parseDate("Thu Apr 7 16:28:52 2011")
        val date2 = parser.parseDate("Thu Apr 7 16:28:52 2011")
        
        assertEquals(date1, date2)
    }
    
    @Test
    def testStatus() {
        val response = """<some_command status="200" status_text="OK"/>"""
        val (code, text) = parser.status(response)
        assertEquals(code, 200)
        assertEquals(text, "OK")
    }
    
    @Test
    def testAuthenticateResponse() {
        val response = """<authenticate_response status="200" status_text="OK"/>"""
        val (code, text) = parser.authenticateResponse(response)
        assertEquals(code, 200)
        assertEquals(text, "OK")
    }
    
    @Test
    def testGetTasksResponse() {
    	// TODO
    }
    
    @Test
    def testGetReportsResponse() {
        val ((statusCode, statusText), content) =
            parser.getReportsResponse(Responses.getReports)
            
        assertEquals(statusCode, 200)
        assertEquals(statusText, "OK")
        assertTrue(content.length == 2)
        assertTrue(content.first.length == 10)
        
        val v = content.first.first
        assertTrue(v.getId() == "a39b37dd-0fde-4774-b557-30c12df483e6")
        assertTrue(v.getNvt().getCvss_base() == 7.1f)
        
        // TODO
    }
    
    @Test
    def testParseCvssBase() {
        assertTrue(parser.parseCvssBase("1.0") == 1.0f)
        assertTrue(parser.parseCvssBase("3.5") == 3.5f)
        assertTrue(parser.parseCvssBase("4.2") == 4.2f)
        assertTrue(parser.parseCvssBase("3.5malformed") == 0.0f)
        assertTrue(parser.parseCvssBase("") == 0.0f)
    }
}


object Responses {
    val getTask = """
        
        """
        
    // warning the cross references inside the document are broken (e.g. result_count)
    val getReports = """
    <get_reports_response status="200" status_text="OK">
	<report id="0197e8aa-ec8f-4150-8d88-bb65f377b097" format_id="d5da9f67-8551-4e51-807b-b6a873d70e34" extension="xml" content_type="text/xml">
		<report id="0197e8aa-ec8f-4150-8d88-bb65f377b097">
			<report_format></report_format>
			<sort>
				<field>
					type<order>descending</order>
				</field>
			</sort>
			<filters>
				hmlgd<phrase></phrase>
				<notes>0</notes>
				<overrides>0</overrides>
				<apply_overrides>0</apply_overrides>
				<result_hosts_only>1</result_hosts_only>
				<min_cvss_base></min_cvss_base>
				<filter>High</filter>
				<filter>Medium</filter>
				<filter>Low</filter>
				<filter>Log</filter>
				<filter>Debug</filter>
			</filters>
			<scan_run_status>Done</scan_run_status>
			<task id="a620d755-d101-4cf5-96b1-cc3d5b32f021">
				<name>damnVulnerableScan</name>
			</task>
			<scan_start>Thu Apr  7 16:04:40 2011</scan_start>
			<ports start="1" max="-1">
				<port>
					<host>10.0.0.101</host>
					general/tcp<threat>High</threat>
				</port>
				<port>
					<host>10.0.0.101</host>
					general/libpng<threat>Medium</threat>
				</port>
				<port>
					<host>10.0.0.101</host>
					general/icmp<threat>Low</threat>
				</port>
				<port>
					<host>10.0.0.101</host>
					ssh (22/tcp)<threat>Low</threat>
				</port>
				<port>
					<host>10.0.0.101</host>
					tftp (69/udp)<threat>Low</threat>
				</port>
				<port>
					<host>10.0.0.101</host>
					general/CPE-T<threat>Log</threat>
				</port>
				<port>
					<host>10.0.0.101</host>
					general/HOST-T<threat>Log</threat>
				</port>
			</ports>
			<result_count>
				<full>96</full>
				<filtered>96</filtered>
				<debug>
					<full>0</full>
					<filtered>0</filtered>
				</debug>
				<hole>
					<full>27</full>
					<filtered>27</filtered>
				</hole>
				<info>
					<full>34</full>
					<filtered>34</filtered>
				</info>
				<log>
					<full>5</full>
					<filtered>5</filtered>
				</log>
				<warning>
					<full>30</full>
					<filtered>30</filtered>
				</warning>
				<false_positive>
					<full>0</full>
					<filtered>0</filtered>
				</false_positive>
			</result_count>
			<results start="1" max="-1">
				<result id="a39b37dd-0fde-4774-b557-30c12df483e6">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.900213">
						<name>Wireshark Multiple Vulnerabilities - Sept08 (Linux)</name>
						<cvss_base>7.1</cvss_base>
						<risk_factor>High</risk_factor>
						<cve>CVE-2008-3146, CVE-2008-3932, CVE-2008-3933</cve>
						<bid>31009</bid>
					</nvt>
					<threat>High</threat>
					<description> Overview : The host is running Wireshark/Ethereal, whichis prone to multiple vulnerabilities.        Vulnerability Insight:        Flaw(s) is/are due to,       - infinite loop errors in the NCP dissector.       - an error when uncompressing zlib-compressed packet data.        Impact : Successful exploitation could result in denial of service        condition or application crash by injecting a series of malformed        packets or by convincing the victim to read a malformed packet. Impact Level : Application Affected Software/OS :        Wireshark versions 1.0.2 and prior on Linux (All). Fix : Upgrade to wireshark 1.0.3 or later. http://www.wireshark.org/download.html References : http://secunia.com/advisories/31674 http://www.frsirt.com/english/advisories/2008/2493 http://www.wireshark.org/security/wnpa-sec-2008-05.html CVSS Score Report :        CVSS Base Score     : 7.1 (AV:N/AC:M/Au:NR/C:N/I:N/A:C)        CVSS Temporal Score : 5.3 Risk factor : HighCVE : CVE-2008-3146, CVE-2008-3932, CVE-2008-3933BID : 31009</description>
				</result>
				<result id="77af993a-6c00-4741-9693-af8473ea0d4a">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.800032">
						<name>Adobe Flash Player Version Detection (Linux)</name>
						<cvss_base></cvss_base>
						<risk_factor>None</risk_factor>
						<cve>NOCVE</cve>
						<bid>NOBID</bid>
					</nvt>
					<threat>Low</threat>
					<description>Adobe Flash Player version 7,0,63,0 was detected on the host</description>
				</result>
				<result id="c49647f3-897d-4a48-8661-80311cb1b2ad">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.800039">
						<name>Wireshark Version Detection (Linux)</name>
						<cvss_base></cvss_base>
						<risk_factor>None</risk_factor>
						<cve>NOCVE</cve>
						<bid>NOBID</bid>
					</nvt>
					<threat>Low</threat>
					<description>Wireshark version 0.99.4 running at location /usr/local/bin/wireshark was detected on the host</description>
				</result>
				<result id="67b3a995-6fe8-450e-9674-1424e52e48d6">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.900070">
						<name>libpng Version Detection</name>
						<cvss_base></cvss_base>
						<risk_factor>None</risk_factor>
						<cve>NOCVE</cve>
						<bid>NOBID</bid>
					</nvt>
					<threat>Low</threat>
					<description>libpng Version 1.2.12 running at location /usr/bin/libpng-config was detected on the host</description>
				</result>
				<result id="8679e4e1-71f6-47d4-826f-41e12422decd">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.900563">
						<name>ImageMagick version Detection (Linux)</name>
						<cvss_base></cvss_base>
						<risk_factor>None</risk_factor>
						<cve>NOCVE</cve>
						<bid>NOBID</bid>
					</nvt>
					<threat>Low</threat>
					<description>ImageMagick version 6.2.9 running at location /usr/local/bin/identify was detected on the host</description>
				</result>
				<result id="9284afce-1643-47ab-b4e7-9cefc3f7e8d9">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.800335">
						<name>OpenSSL Version Detection (Linux)</name>
						<cvss_base></cvss_base>
						<risk_factor>None</risk_factor>
						<cve>NOCVE</cve>
						<bid>NOBID</bid>
					</nvt>
					<threat>Low</threat>
					<description>OpenSSL version vulnerability running at location /usr/bin/openssl-scanner was detected on the host</description>
				</result>
				<result id="bef0110d-8189-48b7-8fdb-5cbaebe4f006">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.800610">
						<name>Cscope Version Detection</name>
						<cvss_base></cvss_base>
						<risk_factor>None</risk_factor>
						<cve>NOCVE</cve>
						<bid>NOBID</bid>
					</nvt>
					<threat>Low</threat>
					<description>Cscope version 15.5 running at location /usr/bin/cscope was detected on the host</description>
				</result>
				<result id="bb149d1c-f68f-448b-9a31-59d6c06cb2bd">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.800995">
						<name>Firewall Builder Version Detection (Linux)</name>
						<cvss_base></cvss_base>
						<risk_factor>None</risk_factor>
						<cve>NOCVE</cve>
						<bid>NOBID</bid>
					</nvt>
					<threat>Low</threat>
					<description>Firewall Builder version 2.0.12 running at location /opt/kde/bin/fwbuilder was detected on the host</description>
				</result>
				<result id="51330b4c-5feb-4323-a736-d19008959e54">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.900643">
						<name>Pango Version Detection</name>
						<cvss_base></cvss_base>
						<risk_factor>None</risk_factor>
						<cve>NOCVE</cve>
						<bid>NOBID</bid>
					</nvt>
					<threat>Low</threat>
					<description>Pango version 1.12.4 running at location /usr/bin/pango-view was detected on the host</description>
				</result>
				<result id="3171c285-945e-40b5-b6c6-6aba765d7eef">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.900827">
						<name>WebDAV Neon Version Detection</name>
						<cvss_base></cvss_base>
						<risk_factor>None</risk_factor>
						<cve>NOCVE</cve>
						<bid>NOBID</bid>
					</nvt>
					<threat>Low</threat>
					<description>WebDAV Neon version 0.25.5 was detected on the host</description>
				</result>
			</results>
			<host_start>
				<host>10.0.0.101</host>
			Thu Apr  7 16:04:42 2011</host_start>
			<host_end>
				<host>10.0.0.101</host>
			Thu Apr  7 16:28:52 2011</host_end>
			<scan_end>Thu Apr  7 16:28:52 2011</scan_end>
		</report>
	</report>
        
   <report id="343435d6-91b0-11de-9478-ffd71f4c6f30" format_id="d5da9f67-8551-4e51-807b-b6a873d70e34" extension="xml" content_type="text/xml">
		<report id="343435d6-91b0-11de-9478-ffd71f4c6f30">
			<report_format></report_format>
			<sort>
				<field>
					type<order>descending</order>
				</field>
			</sort>
			<filters>
				hmlgd<phrase></phrase>
				<notes>0</notes>
				<overrides>0</overrides>
				<apply_overrides>0</apply_overrides>
				<result_hosts_only>1</result_hosts_only>
				<min_cvss_base></min_cvss_base>
				<filter>High</filter>
				<filter>Medium</filter>
				<filter>Low</filter>
				<filter>Log</filter>
				<filter>Debug</filter>
			</filters>
			<scan_run_status>Done</scan_run_status>
			<task id="343435d6-91b0-11de-9478-ffd71f4c6f29">
				<name>Example task</name>
			</task>
			<scan_start>Tue Aug 25 21:48:25 2009</scan_start>
			<ports start="1" max="-1">
				<port>
					<host>localhost</host>
					telnet (23/tcp)<threat>Low</threat>
				</port>
			</ports>
			<result_count>
				<full>1</full>
				<filtered>1</filtered>
				<debug>
					<full>0</full>
					<filtered>0</filtered>
				</debug>
				<hole>
					<full>0</full>
					<filtered>0</filtered>
				</hole>
				<info>
					<full>1</full>
					<filtered>1</filtered>
				</info>
				<log>
					<full>0</full>
					<filtered>0</filtered>
				</log>
				<warning>
					<full>0</full>
					<filtered>0</filtered>
				</warning>
				<false_positive>
					<full>0</full>
					<filtered>0</filtered>
				</false_positive>
			</result_count>
			<results start="1" max="-1">
        <result id="2f502c62-348d-489d-a3ba-9f46b33083a7">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.900675">
						<name>Mutt Version Detection</name>
						<cvss_base></cvss_base>
						<risk_factor>None</risk_factor>
						<cve>NOCVE</cve>
						<bid>NOBID</bid>
					</nvt>
					<threat>Low</threat>
					<description>Mutt version 1.4.2.2i running at location /usr/bin/mutt was detected on the host</description>
				</result>
        
        				<result id="3c0c3500-27a2-48b3-8600-22f83f8f923e">
					<subnet>10.0.0.101</subnet>
					<host>10.0.0.101</host>
					<port>general/tcp</port>
					<nvt oid="1.3.6.1.4.1.25623.1.0.902401">
						<name>Adobe Flash Player Remote Memory Corruption Vulnerability (Linux)</name>
						<cvss_base>9.3</cvss_base>
						<risk_factor>Critical</risk_factor>
						<cve>CVE-2011-0609</cve>
						<bid>46860</bid>
					</nvt>
					<threat>High</threat>
					<description>  Overview: This host is installed with Adobe Flash Player and is prone to  memory corruption vulnerability.  Vulnerability Insight:  The flaw is caused due to an error when handling the &apos;SWF&apos; file, which allows  attackers to execute arbitrary code or cause a denial of service via crafted  flash content.  Impact:  Successful exploitation will let attackers to execute arbitrary code or cause  a denial of service.  Impact Level: Application/System  Affected Software/OS:  Adobe Flash Player version 10.2.152.33 and prior on Linux.  Fix: Upgrade to Adobe Flash Player version 10.2.153.1 or later.  For details refer, http://www.adobe.com/downloads/  References:  http://www.adobe.com/support/security/bulletins/apsb11-06.html  http://www.adobe.com/support/security/advisories/apsa11-01.html CVE : CVE-2011-0609BID : 46860</description>
				</result>
			</results>
			<host_start>
				<host>localhost</host>
			Tue Aug 25 21:48:26 2009</host_start>
			<host_end>
				<host>localhost</host>
			Tue Aug 25 21:52:15 2009</host_end>
			<scan_end>Tue Aug 25 21:52:16 2009</scan_end>
		</report>
	</report>
</get_reports_response>
        """

}
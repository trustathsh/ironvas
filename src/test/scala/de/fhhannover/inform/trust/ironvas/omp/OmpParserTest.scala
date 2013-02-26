/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.omp
 * File:    OmpParserTest.scala
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

package de.fhhannover.inform.trust.ironvas.omp

import org.junit.Assert._
import org.junit.Test
import org.junit.Before
import java.util.Calendar
import org.junit.Ignore
import org.junit.runner.RunWith
import org.junit.runners.Suite

class OmpParserTest {

  var parser: OmpParser = _

  @Before
  def setUp() {
    parser = new OmpParser
  }

  @Test
  def testParseDateValidValues() {
    val dates = Map(
      "Thu Apr 7 16:28:52 2011" -> (3, 7, 16, 28, 52, 2011),
      "Tue Aug 25 21:48:25 2009" -> (7, 25, 21, 48, 25, 2009),
      "Wed Jun 30 21:49:08 1993" -> (5, 30, 21, 49, 8, 1993),
      "Wed Mar  7 21:27:59 2012" -> (2, 7, 21, 27, 59, 2012))
    for (item <- dates) {
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
  def testParseDateMalformedValues() {
    val dates = List(
      "",
      "somestring",
      "ThuApr 7 16:28:52 2011", // missing space
      "Tue Aug 21:48:25 2009", // missing day
      "Wed Mar  7 21:27:59" // missing year
      )
    for (item <- dates) {
      val date = parser.parseDate(item)
      assertEquals(0, date.getTime())
    }
  }

  @Test
  def testParseDateEquals() {
    val date1 = parser.parseDate("Thu Apr 7 16:28:52 2011")
    val date2 = parser.parseDate("Thu Apr 7 16:28:52 2011")
    assertEquals(date1, date2)
    assertEquals(date2, date1)
  }

  @Test
  def testStatusOKSingleTag() {
    val response = """<some_command status="200" status_text="OK"/>"""
    val (code, text) = parser.status(response)
    assertEquals(code, 200)
    assertEquals(text, "OK")
  }

  @Test
  def testStatusOKDocument() {
    val (code, text) = parser.status(Responses.getReports)
    assertEquals(code, 200)
    assertEquals(text, "OK")
  }

  @Test
  def testStatusMissing() {
    val response = """<some_command />"""
    val (code, text) = parser.status(response)
    assertEquals(700, code)
    assertEquals("Parser Error", text)
  }

  @Test
  def testAuthenticateResponse() {
    val response = """<authenticate_response status="200" status_text="OK"/>"""
    val (code, text) = parser.authenticateResponse(response)
    assertEquals(code, 200)
    assertEquals(text, "OK")
  }

  @Test
  def testGetTasksResponseElementSize() {
    val (_, tasks) = parser.getTasksResponse(Responses.getTasks)
    assertEquals(3, tasks.size)
  }

  @Test
  def testGetTasksResponseLastReports() {
    val lastReportIds = List(
      "3f892e8b-2d6c-4ce4-ad36-d6ccd9e9779c",
      "b1409e73-621d-4cc2-9578-3bda5c2a89d8",
      "ff8cd5e6-c3e4-4d0a-bc9a-18e401430a8a")

    val (_, tasks) = parser.getTasksResponse(Responses.getTasks)
    for (task <- tasks) {
      assertTrue(lastReportIds.contains(task.lastReportId))
    }
  }

  @Test
  def testGetReportsResponseElementSize() {
    val ((_, _), content) = parser.getReportsResponse(Responses.getReports)

    // we expect 2 reports
    assertTrue(content.length == 2)

    // the first report contains 10 elements
    assertTrue(content.head.length == 10)

    // the second report contains 2 elements
    assertTrue(content.last.length == 2)
  }

  @Test
  def testGetReportsResponseVulnerabilityIds() {
    val ((_, _), content) = parser.getReportsResponse(Responses.getReports)
    val lastReport = content.last
    val ids = List(
      "2f502c62-348d-489d-a3ba-9f46b33083a7",
      "3c0c3500-27a2-48b3-8600-22f83f8f923e")
    val zipped = lastReport.zip(ids)
    for ((vulnerability, id) <- zipped) {
      assertEquals(id, vulnerability.getId())
    }
  }

  @Test
  def testGetReportsResponseNvtOid() {
    val ((_, _), content) = parser.getReportsResponse(Responses.getReports)
    val lastReport = content.last
    val ids = List(
      "1.3.6.1.4.1.25623.1.0.900675",
      "1.3.6.1.4.1.25623.1.0.902401")
    val zipped = lastReport.zip(ids)
    for ((vulnerability, id) <- zipped) {
      assertEquals(id, vulnerability.getNvt().getOid())
    }
  }

  @Test
  def testGetReportsResponseNvtName() {
    val ((_, _), content) = parser.getReportsResponse(Responses.getReports)
    val lastReport = content.last
    val names = List(
      "Mutt Version Detection",
      "Adobe Flash Player Remote Memory Corruption Vulnerability (Linux)")
    val zipped = lastReport.zip(names)
    for ((vulnerability, name) <- zipped) {
      assertEquals(name, vulnerability.getNvt().getName())
    }
  }

  @Test
  def testParseCvssBaseValidValues() {
    assertTrue(parser.parseCvssBase("1.0") == 1.0f)
    assertTrue(parser.parseCvssBase("3.5") == 3.5f)
    assertTrue(parser.parseCvssBase("4.2") == 4.2f)
  }

  @Test
  def testParseCvssBaseMalformedValues() {
    assertTrue(parser.parseCvssBase("3.5malformed") == -1.0f)
    assertTrue(parser.parseCvssBase("somestring") == -1.0f)
  }

  @Test
  def testParseCvssBaseEmptyValues() {
    assertTrue(parser.parseCvssBase("") == 0.0f)
    assertTrue(parser.parseCvssBase("None") == 0.0f)
  }

}

object Responses {

  val getTasks = """
<get_tasks_response status="200" status_text="OK">
  <task_count>3</task_count>
  <sort>
    <field>ROWID<order>ascending</order></field>
  </sort>
  <apply_overrides>0</apply_overrides>
  <task id="4e4ec115-d138-43b3-a919-872e3edd1278">
    <name>DVL-task</name>
    <comment/>
    <config id="74db13d6-7489-11df-91b9-002264764cea">
      <name>Full and very deep ultimate</name>
    </config>
    <escalator id="">
      <name/>
    </escalator>
    <target id="06dbae40-4b2e-4975-9df2-d1bae50f845c">
      <name>DVL-host</name>
    </target>
    <slave id="">
      <name/>
    </slave>
    <status>Done</status>
    <progress>-1</progress>
    <report_count>1<finished>1</finished></report_count>
    <trend/>
    <schedule id="">
      <name/>
      <next_time>over</next_time>
    </schedule>
    <first_report>
      <report id="3f892e8b-2d6c-4ce4-ad36-d6ccd9e9779c">
        <timestamp>Wed Mar  7 14:47:13 2012</timestamp>
        <result_count>
          <debug>0</debug>
          <hole>0</hole>
          <info>2</info>
          <log>11</log>
          <warning>0</warning>
          <false_positive>0</false_positive>
        </result_count>
      </report>
    </first_report>
    <last_report>
      <report id="3f892e8b-2d6c-4ce4-ad36-d6ccd9e9779c">
        <timestamp>Wed Mar  7 14:47:13 2012</timestamp>
        <result_count>
          <debug>0</debug>
          <hole>0</hole>
          <info>2</info>
          <log>11</log>
          <warning>0</warning>
          <false_positive>0</false_positive>
        </result_count>
      </report>
    </last_report>
  </task>
  <task id="ff0ab0bd-cf25-4bd1-a2f3-40194c91b7cf">
    <name>vms</name>
    <comment/>
    <config id="74db13d6-7489-11df-91b9-002264764cea">
      <name>Full and very deep ultimate</name>
    </config>
    <escalator id="">
      <name/>
    </escalator>
    <target id="a8325a53-8453-4d65-9277-ec0a28dbf58c">
      <name>vms</name>
    </target>
    <slave id="">
      <name/>
    </slave>
    <status>Done</status>
    <progress>-1</progress>
    <report_count>1<finished>1</finished></report_count>
    <trend/>
    <schedule id="">
      <name/>
      <next_time>over</next_time>
    </schedule>
    <first_report>
      <report id="ff8cd5e6-c3e4-4d0a-bc9a-18e401430a8a">
        <timestamp>Wed Mar  7 19:30:30 2012</timestamp>
        <result_count>
          <debug>0</debug>
          <hole>0</hole>
          <info>2</info>
          <log>10</log>
          <warning>1</warning>
          <false_positive>0</false_positive>
        </result_count>
      </report>
    </first_report>
    <last_report>
      <report id="ff8cd5e6-c3e4-4d0a-bc9a-18e401430a8a">
        <timestamp>Wed Mar  7 19:30:30 2012</timestamp>
        <result_count>
          <debug>0</debug>
          <hole>0</hole>
          <info>2</info>
          <log>10</log>
          <warning>1</warning>
          <false_positive>0</false_positive>
        </result_count>
      </report>
    </last_report>
  </task>
  <task id="fce7bb27-b670-4691-bfbc-3acac73679e2">
    <name>DVL-local</name>
    <comment/>
    <config id="374d800e-5b89-4afe-b160-bbc869027ce3">
      <name>DVL-config-local</name>
    </config>
    <escalator id="">
      <name/>
    </escalator>
    <target id="06dbae40-4b2e-4975-9df2-d1bae50f845c">
      <name>DVL-host</name>
    </target>
    <slave id="">
      <name/>
    </slave>
    <status>Done</status>
    <progress>-1</progress>
    <report_count>2<finished>2</finished></report_count>
    <trend>up</trend>
    <schedule id="">
      <name/>
      <next_time>over</next_time>
    </schedule>
    <first_report>
      <report id="d67678ba-2c54-4f77-84dd-bfe9e3c45f13">
        <timestamp>Thu Mar  8 19:30:09 2012</timestamp>
        <result_count>
          <debug>0</debug>
          <hole>0</hole>
          <info>4</info>
          <log>17</log>
          <warning>0</warning>
          <false_positive>0</false_positive>
        </result_count>
      </report>
    </first_report>
    <last_report>
      <report id="b1409e73-621d-4cc2-9578-3bda5c2a89d8">
        <timestamp>Thu Mar  8 20:23:49 2012</timestamp>
        <result_count>
          <debug>0</debug>
          <hole>0</hole>
          <info>4</info>
          <log>17</log>
          <warning>0</warning>
          <false_positive>0</false_positive>
        </result_count>
      </report>
    </last_report>
    <second_last_report>
      <report id="d67678ba-2c54-4f77-84dd-bfe9e3c45f13">
        <timestamp>Thu Mar  8 19:30:09 2012</timestamp>
        <result_count>
          <debug>0</debug>
          <hole>0</hole>
          <info>4</info>
          <log>17</log>
          <warning>0</warning>
          <false_positive>0</false_positive>
        </result_count>
      </report>
    </second_last_report>
  </task>
</get_tasks_response>
    """

  val getTargets = """
<get_targets_response status="200" status_text="OK">
  <target id="b493b7a8-7489-11df-a3ec-002264764cea">
    <name>Localhost</name>
    <hosts>localhost</hosts>
    <max_hosts>1</max_hosts>
    <comment></comment>
    <in_use>1</in_use>
    <port_range></port_range>
    <ssh_lsc_credential id="">
      <name></name>
    </ssh_lsc_credential>
    <smb_lsc_credential id="">
      <name></name>
    </smb_lsc_credential>
    <tasks></tasks>
  </target>
  <target id="a63d8644-10b7-4af1-88aa-b32ba2c114db">
    <name>DVL host</name>
    <hosts>10.0.0.7</hosts>
    <max_hosts>1</max_hosts>
    <comment></comment>
    <in_use>1</in_use>
    <port_range>default</port_range>
    <ssh_lsc_credential id="ffc27f6c-474f-4890-8234-536f1bbd9b45">
      <name>DVL root</name>
    </ssh_lsc_credential>
    <smb_lsc_credential id="">
      <name></name>
    </smb_lsc_credential>
    <tasks>
      <task id="1c3137b3-b2ef-420c-9527-a4e3a357e68f">
        <name>ironvas task</name>
      </task>
    </tasks>
  </target>
  <target id="d37508a1-8941-4000-96ac-f59a26eef23a">
    <name>ironvas:10.1.1.1</name>
    <hosts>10.1.1.1</hosts>
    <max_hosts>1</max_hosts>
    <comment></comment>
    <in_use>1</in_use>
    <port_range>default</port_range>
    <ssh_lsc_credential id="">
      <name></name>
    </ssh_lsc_credential>
    <smb_lsc_credential id="">
      <name></name>
    </smb_lsc_credential>
    <tasks>
      <task id="cb3ecd33-7d38-4418-a2b7-ba34e969c896">
        <name>ironvas:10.1.1.1</name>
      </task>
    </tasks>
  </target>
</get_targets_response>
    """

  val getReports = """
    <get_reports_response status="200" status_text="OK">
	<report id="0197e8aa-ec8f-4150-8d88-bb65f377b097" format_id="d5da9f67-8551-4e51-807b-b6a873d70e34" extension="xml" content_type="text/xml">
		<report id="0197e8aa-ec8f-4150-8d88-bb65f377b097">
			<scan_run_status>Done</scan_run_status>
			<task id="a620d755-d101-4cf5-96b1-cc3d5b32f021">
				<name>damnVulnerableScan</name>
			</task>
			<scan_start>Thu Apr  7 16:04:40 2011</scan_start>
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
			<scan_run_status>Done</scan_run_status>
			<task id="343435d6-91b0-11de-9478-ffd71f4c6f29">
				<name>Example task</name>
			</task>
			<scan_start>Tue Aug 25 21:48:25 2009</scan_start>
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

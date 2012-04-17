/*
 * Project: ironvas
 * Package: test.java.de.fhhannover.inform.trust.ironvas.converter
 * File:    FilterEventUpdateConverterTest.java
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

package de.fhhannover.inform.trust.ironvas.converter;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;

import de.fhhannover.inform.trust.ifmapj.messages.PublishElement;
import de.fhhannover.inform.trust.ironvas.Nvt;
import de.fhhannover.inform.trust.ironvas.RiskfactorLevel;
import de.fhhannover.inform.trust.ironvas.ThreatLevel;
import de.fhhannover.inform.trust.ironvas.Vulnerability;

import static org.junit.Assert.*;

public class FilterEventUpdateConverterTest {
	
	private FilterEventUpdateConverter converter;
	
	private Vulnerability high;
	private Vulnerability critical;
	
	@Before
	public void setUp() {
		Map<RiskfactorLevel, Boolean> filterCondition =
				new HashMap<RiskfactorLevel, Boolean>();
		filterCondition.put(RiskfactorLevel.Unknown, false);
		filterCondition.put(RiskfactorLevel.None, false);
		filterCondition.put(RiskfactorLevel.Low, false);
		filterCondition.put(RiskfactorLevel.Medium, false);
		filterCondition.put(RiskfactorLevel.High, false);
		filterCondition.put(RiskfactorLevel.Critical, true);
		
		
		String publisherId = "ironvas";
		String openVASId = "openvas@example.test";
		converter = new FilterEventUpdateConverter(
				publisherId,
				openVASId,
				filterCondition);
		
		high = new Vulnerability("", new Date(0), "", "", "", ThreatLevel.High, "",
				new Nvt("", "", 0.0f, RiskfactorLevel.High, "", ""));
		critical = new Vulnerability("", new Date(0), "", "", "", ThreatLevel.High, "",
				new Nvt("", "", 0.0f, RiskfactorLevel.Critical, "", ""));
	}
	
	@Test
	public void testToUpdateSize() {
		Set<Vulnerability> vulnerabilities = new HashSet<Vulnerability>();
		vulnerabilities.add(critical);
		vulnerabilities.add(high);
		
		List<PublishElement> publish = converter.toUpdates(vulnerabilities);
		assertEquals(1, publish.size());
	}

}

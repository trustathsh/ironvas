/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.converter
 * File:    FilterEventUpdateConverterTest.java
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

import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
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
	
	private Set<Vulnerability> vulnerabilities;
	
	@Before
	public void setUp() {
		vulnerabilities = new HashSet<Vulnerability>();
		vulnerabilities.add(
				new Vulnerability("", new Date(0), "", "", "", ThreatLevel.High, "",
						new Nvt("", "", 0.0f, RiskfactorLevel.High, "", "")));
		vulnerabilities.add(
				new Vulnerability("", new Date(0), "", "", "", ThreatLevel.High, "",
						new Nvt("", "", 0.0f, RiskfactorLevel.Critical, "", "")));
	}
	
	@Test
	public void testToUpdateSizeFilterNothing() {
		Map<RiskfactorLevel, Boolean> filterUpdate =
				new HashMap<RiskfactorLevel, Boolean>();
		for (RiskfactorLevel r : RiskfactorLevel.values()) {
			filterUpdate.put(r, false);
		}
		
		Map<RiskfactorLevel, Boolean> filterNotify =
				new HashMap<RiskfactorLevel, Boolean>();
		for (RiskfactorLevel r : RiskfactorLevel.values()) {
			filterNotify.put(r, false);
		}
		
		FilterEventUpdateConverter converter =
				new FilterEventUpdateConverter(
						"publisher-id", "openvas",
						filterUpdate, filterNotify);
		List<PublishElement> publish = converter.toUpdates(vulnerabilities);
		assertEquals(0, publish.size());
	}
	
	@Test
	public void testToUpdateSizeFilterOnlyNotify() {
		Map<RiskfactorLevel, Boolean> filterUpdate =
				new HashMap<RiskfactorLevel, Boolean>();
		for (RiskfactorLevel r : RiskfactorLevel.values()) {
			filterUpdate.put(r, false);
		}
		
		Map<RiskfactorLevel, Boolean> filterNotify =
				new HashMap<RiskfactorLevel, Boolean>();
		for (RiskfactorLevel r : RiskfactorLevel.values()) {
			filterNotify.put(r, true);
		}
		
		FilterEventUpdateConverter converter =
				new FilterEventUpdateConverter(
						"publisher-id", "openvas",
						filterUpdate, filterNotify);
		List<PublishElement> publish = converter.toUpdates(vulnerabilities);
		assertEquals(2, publish.size());
	}
	
	@Test
	public void testToUpdateSizeFilterOnlyUpdate() {
		Map<RiskfactorLevel, Boolean> filterUpdate =
				new HashMap<RiskfactorLevel, Boolean>();
		for (RiskfactorLevel r : RiskfactorLevel.values()) {
			filterUpdate.put(r, true);
		}
		
		Map<RiskfactorLevel, Boolean> filterNotify =
				new HashMap<RiskfactorLevel, Boolean>();
		for (RiskfactorLevel r : RiskfactorLevel.values()) {
			filterNotify.put(r, false);
		}
		
		FilterEventUpdateConverter converter =
				new FilterEventUpdateConverter(
						"publisher-id", "openvas",
						filterUpdate, filterNotify);
		List<PublishElement> publish = converter.toUpdates(vulnerabilities);
		assertEquals(2, publish.size());
	}
	
	@Test
	public void testToUpdateSizeFilterMixed() {
		Map<RiskfactorLevel, Boolean> filterUpdate =
				new HashMap<RiskfactorLevel, Boolean>();
		filterUpdate.put(RiskfactorLevel.Unknown, false);
		filterUpdate.put(RiskfactorLevel.None, false);
		filterUpdate.put(RiskfactorLevel.Low, false);
		filterUpdate.put(RiskfactorLevel.Medium, false);
		filterUpdate.put(RiskfactorLevel.High, true);
		filterUpdate.put(RiskfactorLevel.Critical, true);
		
		Map<RiskfactorLevel, Boolean> filterNotify =
				new HashMap<RiskfactorLevel, Boolean>();
		filterNotify.put(RiskfactorLevel.Unknown, false);
		filterNotify.put(RiskfactorLevel.None, false);
		filterNotify.put(RiskfactorLevel.Low, false);
		filterNotify.put(RiskfactorLevel.Medium, false);
		filterNotify.put(RiskfactorLevel.High, false);
		filterNotify.put(RiskfactorLevel.Critical, true);
		
		FilterEventUpdateConverter converter =
				new FilterEventUpdateConverter(
						"publisher-id", "openvas",
						filterUpdate, filterNotify);
		List<PublishElement> publish = converter.toUpdates(vulnerabilities);
		assertEquals(3, publish.size());
	}
	
	@Test
	public void testToDeleteSize() {
		Map<RiskfactorLevel, Boolean> filterUpdate =
				new HashMap<RiskfactorLevel, Boolean>();
		filterUpdate.put(RiskfactorLevel.Unknown, false);
		filterUpdate.put(RiskfactorLevel.None, false);
		filterUpdate.put(RiskfactorLevel.Low, false);
		filterUpdate.put(RiskfactorLevel.Medium, false);
		filterUpdate.put(RiskfactorLevel.High, true);
		filterUpdate.put(RiskfactorLevel.Critical, true);
		
		Map<RiskfactorLevel, Boolean> filterNotify =
				new HashMap<RiskfactorLevel, Boolean>();
		filterNotify.put(RiskfactorLevel.Unknown, false);
		filterNotify.put(RiskfactorLevel.None, false);
		filterNotify.put(RiskfactorLevel.Low, false);
		filterNotify.put(RiskfactorLevel.Medium, false);
		filterNotify.put(RiskfactorLevel.High, false);
		filterNotify.put(RiskfactorLevel.Critical, true);
		
		FilterEventUpdateConverter converter =
				new FilterEventUpdateConverter(
						"publisher-id", "openvas",
						filterUpdate, filterNotify);
		List<PublishElement> publish = converter.toDeletes(vulnerabilities);
		assertEquals(2, publish.size());
	}

}

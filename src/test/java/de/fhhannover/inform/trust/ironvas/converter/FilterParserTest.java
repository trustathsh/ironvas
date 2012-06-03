/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.converter
 * File:    FilterParserTest.java
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

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

import de.fhhannover.inform.trust.ironvas.RiskfactorLevel;

public class FilterParserTest {
	
	private FilterParser parser;
	
	@Before
	public void setUp() {
		parser = new FilterParser();
	}
	
	@Test
	public void testParseALL() {
		FilterParser parser = new FilterParser();
		
		Map<RiskfactorLevel, Boolean> expectedALL =
				new HashMap<RiskfactorLevel, Boolean>();
		for (RiskfactorLevel r : RiskfactorLevel.values()) {
			expectedALL.put(r, true);
		}
		
		String line = "ALL";
		Map<RiskfactorLevel, Boolean> actual = parser.parseLine(line);
		assertEquals(expectedALL, actual);
	}
	
	@Test
	public void testParse() {
		String line = "High Critical";
		String reversed = "Critical High";
		
		Map<RiskfactorLevel, Boolean> expected =
				new HashMap<RiskfactorLevel, Boolean>();
		for (RiskfactorLevel r : RiskfactorLevel.values()) {
			expected.put(r, false);
		}
		expected.put(RiskfactorLevel.Critical, true);
		expected.put(RiskfactorLevel.High, true);
		
		assertEquals(expected, parser.parseLine(line));
		assertEquals(expected, parser.parseLine(reversed));
	}
	
	@Test(expected=RuntimeException.class)
	public void testParseMalformed() {
		parser.parseLine("not a valid value");
	}
	
	@Test
	public void testParseEmpty() {
		String line = "";
		
		Map<RiskfactorLevel, Boolean> expected =
				new HashMap<RiskfactorLevel, Boolean>();
		for (RiskfactorLevel r : RiskfactorLevel.values()) {
			expected.put(r, false);
		}
		
		assertEquals(expected, parser.parseLine(line));
	}

}

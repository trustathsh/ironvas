/*
 * Project: ironvas
 * Package: main.java.de.fhhannover.inform.trust.ironvas.converter
 * File:    FilterParser.java
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

import de.fhhannover.inform.trust.ironvas.RiskfactorLevel;

public class FilterParser {
	
	public Map<RiskfactorLevel, Boolean> parseLine(String line) {
		Map<RiskfactorLevel, Boolean> filter =
				new HashMap<RiskfactorLevel, Boolean>();
		
		// default is all false
		for (RiskfactorLevel r : RiskfactorLevel.values()) {
			filter.put(r, false);
		}
		
		String trimmed = line.trim();

		if (trimmed.equals("")) {
			return filter;
		}
		else if (trimmed.equals("ALL")) {
			for (RiskfactorLevel r : RiskfactorLevel.values()) {
				filter.put(r, true);
			}
		}
		else {
			String[] values = line.split("\\s+");
			for (String v : values) {
				if (v.equals(RiskfactorLevel.Critical.toString())) {
					filter.put(RiskfactorLevel.Critical, true);
				}
				else if (v.equals(RiskfactorLevel.High.toString())) {
					filter.put(RiskfactorLevel.High, true);
				}
				else if (v.equals(RiskfactorLevel.Medium.toString())) {
					filter.put(RiskfactorLevel.Medium, true);
				}
				else if (v.equals(RiskfactorLevel.Low.toString())) {
					filter.put(RiskfactorLevel.Low, true);
				}
				else if (v.equals(RiskfactorLevel.None.toString())) {
					filter.put(RiskfactorLevel.None, true);
				}
				else if (v.equals(RiskfactorLevel.None.toString())) {
					filter.put(RiskfactorLevel.Unknown, true);
				}
				else {
					throw new RuntimeException("unknown value '"+v+"' in filter string");
				}
			}
		}
		return filter;
	}

}

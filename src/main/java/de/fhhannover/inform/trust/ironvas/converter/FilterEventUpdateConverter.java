/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.converter
 * File:    FilterEventUpdateConverter.java
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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import de.fhhannover.inform.trust.ifmapj.messages.PublishElement;
import de.fhhannover.inform.trust.ironvas.RiskfactorLevel;
import de.fhhannover.inform.trust.ironvas.Vulnerability;

/**
 * The <code>FilterEventUpdateConverter</code> converts {@link Vulnerability}
 * objects into IF-MAP event metadata, it can be configured to filter the set
 * of mapped {@link Vulnerability} objects according to their
 * {@link RiskfactorLevel}.
 * 
 * @author Ralf Steuerwald
 *
 */
public class FilterEventUpdateConverter extends FullEventUpdateConverter {
	
	private Map<RiskfactorLevel, Boolean> filterUpdate;
	private Map<RiskfactorLevel, Boolean> filterNotify;

	public FilterEventUpdateConverter(
			Map<RiskfactorLevel, Boolean> filterUpdate,
			Map<RiskfactorLevel, Boolean> filterNotify) {
		this.filterUpdate = new HashMap<RiskfactorLevel, Boolean>(filterUpdate);
		this.filterNotify = new HashMap<RiskfactorLevel, Boolean>(filterNotify);
	}

	@Override
	public List<PublishElement> toUpdates(Set<Vulnerability> vulnerabilities) {
		List<PublishElement> result = new ArrayList<PublishElement>();
		for (Vulnerability v : vulnerabilities) {
			RiskfactorLevel level = v.getNvt().getRisk_factor();
			
			if (filterUpdate.get(level)) {
				result.add(singleUpdate(v));
			}
			if (filterNotify.get(level)) {
				result.add(singleUpdate(v, true));
			}
		}
		return result;
	}
	
	@Override
	public List<PublishElement> toDeletes(Set<Vulnerability> vulnerabilities) {
		List<PublishElement> result = new ArrayList<PublishElement>();
		for (Vulnerability v : vulnerabilities) {
			RiskfactorLevel level = v.getNvt().getRisk_factor();
			
			if (filterUpdate.get(level)) {
				result.add(singleDelete(v));
			}
			// we don't need to delete the notifys explicitly, because metadata
			// will be deleted only based on their content
		}
		return result;
	}

}

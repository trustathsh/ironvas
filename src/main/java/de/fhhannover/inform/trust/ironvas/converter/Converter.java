/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.converter
 * File:    Converter.java
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

import java.util.List;
import java.util.Set;

import de.fhhannover.inform.trust.ifmapj.messages.PublishElement;
import de.fhhannover.inform.trust.ironvas.Vulnerability;

/**
 * A <code>Converter</code> is capable of mapping {@link Vulnerability}
 * instances to IF-MAP data structures for processing with <code>ifmapj</code>.
 * The implementation of this interface is free to choose if a
 * {@link Vulnerability} instance is mapped exact to one IF-MAP representation
 * (e.g. event) or if the information is distributed over more than one
 * representation (e.g. event and some special schema).
 * Furthermore the implementation of a <code>Converter</code> is free to
 * choose what kind of publish operation (update or notify) is executed.
 * <p>
 * Note that the transformation must be symmetric for updates and deletes. This
 * means that if one {@link Vulnerability} object is mapped to more than
 * one representation, the delete-mapping for the same {@link Vulnerability}
 * object must result in a complete delete operation for all previously
 * generated representation of that {@link Vulnerability}. 
 * 
 * @author Ralf Steuerwald
 *
 */
public interface Converter {
	
	public List<PublishElement> toUpdates(Set<Vulnerability> vulnerabilities);
	public List<PublishElement> toDeletes(Set<Vulnerability> vulnerabilities);
	
	public void setPublisherId(String publisherId);
	public void setOpenVasServerId(String openVasServerId);

}

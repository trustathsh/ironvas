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
 * This file is part of ironvas, version 0.1.2, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2011 - 2013 Trust@HsH
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

import java.util.List;
import java.util.Set;

import de.hshannover.f4.trust.ifmapj.messages.PublishElement;
import de.hshannover.f4.trust.ironvas.Context;
import de.hshannover.f4.trust.ironvas.Vulnerability;

/**
 * A <code>Converter</code> is capable of mapping {@link Vulnerability}
 * instances to IF-MAP data structures for processing with <code>ifmapj</code>.
 * The implementation of this interface is free to choose if a
 * {@link Vulnerability} instance is mapped exact to one IF-MAP representation
 * (e.g. event) or if the information is distributed over more than one
 * representation (e.g. event and some special schema). Furthermore the
 * implementation of a <code>Converter</code> is free to choose what kind of
 * publish operation (update or notify) is executed.
 * <p>
 * Note that the transformation must be symmetric for updates and deletes. This
 * means that if one {@link Vulnerability} object is mapped to more than one
 * representation, the delete-mapping for the same {@link Vulnerability} object
 * must result in a complete delete operation for all previously generated
 * representation of that {@link Vulnerability}.
 *
 * @author Ralf Steuerwald
 *
 */
public interface Converter {

    public List<PublishElement> toUpdates(Set<Vulnerability> vulnerabilities);

    public List<PublishElement> toDeletes(Set<Vulnerability> vulnerabilities);

    public Converter setContext(Context context);

}

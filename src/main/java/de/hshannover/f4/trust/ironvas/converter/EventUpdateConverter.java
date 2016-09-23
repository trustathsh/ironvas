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
 * This file is part of ironvas, version 0.1.7, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2011 - 2016 Trust@HsH
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

import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.w3c.dom.Document;

import de.hshannover.f4.trust.ifmapj.IfmapJ;
import de.hshannover.f4.trust.ifmapj.binding.IfmapStrings;
import de.hshannover.f4.trust.ifmapj.identifier.Identifiers;
import de.hshannover.f4.trust.ifmapj.identifier.IpAddress;
import de.hshannover.f4.trust.ifmapj.messages.PublishDelete;
import de.hshannover.f4.trust.ifmapj.messages.PublishElement;
import de.hshannover.f4.trust.ifmapj.messages.PublishUpdate;
import de.hshannover.f4.trust.ifmapj.messages.Requests;
import de.hshannover.f4.trust.ifmapj.metadata.EventType;
import de.hshannover.f4.trust.ifmapj.metadata.Significance;
import de.hshannover.f4.trust.ifmapj.metadata.StandardIfmapMetadataFactory;
import de.hshannover.f4.trust.ironvas.Context;
import de.hshannover.f4.trust.ironvas.RiskfactorLevel;
import de.hshannover.f4.trust.ironvas.ThreatLevel;
import de.hshannover.f4.trust.ironvas.Vulnerability;

/**
 * The <code>EventUpdateConverter</code> maps {@link Vulnerability} objects to
 * IF-MAP event metadata and choose the update operation for all
 * vulnerabilities. No filtering is applied to the set of vulnerabilities.
 *
 * @author Ralf Steuerwald
 *
 */
public class EventUpdateConverter implements Converter {

    private StandardIfmapMetadataFactory mMetadataFactory = IfmapJ
            .createStandardMetadataFactory();

    private Context mContext;

    private SimpleDateFormat mDateFormat = new SimpleDateFormat(
            "yyyy-MM-dd'T'HH:mm:ssZ");

    public PublishElement singleUpdate(Vulnerability v) {
        IpAddress ip = Identifiers.createIp4(v.getHost());
        Document metadata = mMetadataFactory.createEvent(v.getNvt().getName(), // name
                mDateFormat.format(v.getTimestamp()), // discovered-time
                mContext.getOpenVasServerId(), // discoverer-id
                (int) (v.getNvt().getCvssBase() * 10 + 0.5), // magnitude
                                                                // (0-100)
                0, // confidence TODO define
                mapSignificance(v.getNvt().getRiskFactor()), // significance
                EventType.cve, // type
                v.getId(), // other-type-definition
                v.getDescription(), // information
                v.getNvt().getCve() // vulnerability-uri
                );

        PublishUpdate update = Requests.createPublishUpdate();
        update.setIdentifier1(ip);
        update.addMetadata(metadata);

        return update;
    }

    public PublishDelete singleDelete(Vulnerability v) {
        PublishDelete delete = Requests.createPublishDelete();

        String filter = String.format("meta:event[@ifmap-publisher-id='%s' "
                + "and other-type-definition='%s']",
                mContext.getIfmapPublisherId(), v.getId());

        IpAddress ip = Identifiers.createIp4(v.getHost());
        delete.addNamespaceDeclaration("meta", IfmapStrings.STD_METADATA_NS_URI);
        delete.setFilter(filter);
        delete.setIdentifier1(ip);

        return delete;
    }

    @Override
    public List<PublishElement> toUpdates(Set<Vulnerability> vulnerabilities) {
        List<PublishElement> result = new ArrayList<PublishElement>();
        for (Vulnerability v : vulnerabilities) {
            result.add(singleUpdate(v));
        }
        return result;
    }

    @Override
    public List<PublishElement> toDeletes(Set<Vulnerability> vulnerabilities) {
        List<PublishElement> result = new ArrayList<PublishElement>();
        for (Vulnerability v : vulnerabilities) {
            result.add(singleDelete(v));
        }
        return result;
    }

    private Significance mapSignificance(RiskfactorLevel riskFactor) {
        switch (riskFactor) {
        case Critical:
            return Significance.critical;
        case High:
            return Significance.critical;
        case Medium:
            return Significance.important;
        case Low:
            return Significance.important;
        case None:
            return Significance.informational;
        default:
            return Significance.informational;
        }
    }

    private Significance mapSignificance(ThreatLevel threatLevel) {
        switch (threatLevel) {
        case High:
            return Significance.critical;
        case Medium:
            return Significance.important;
        case Low:
            return Significance.important;
        case Log:
            return Significance.informational;
        case Debug:
            return Significance.informational;
        default:
            return Significance.informational;
        }
    }

    @Override
    public Converter setContext(Context context) {
        if (context == null) {
            throw new IllegalArgumentException("context cannot be null");
        }
        this.mContext = context;
        return this;
    }

}

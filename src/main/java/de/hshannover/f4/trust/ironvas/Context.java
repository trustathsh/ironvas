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
 * This file is part of ironvas, version 0.1.4, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2011 - 2015 Trust@HsH
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
package de.hshannover.f4.trust.ironvas;

import java.util.List;
import java.util.logging.Logger;

import de.hshannover.f4.trust.ifmapj.binding.IfmapStrings;
import de.hshannover.f4.trust.ifmapj.channel.SSRC;
import de.hshannover.f4.trust.ifmapj.exception.IfmapErrorResult;
import de.hshannover.f4.trust.ifmapj.exception.IfmapException;
import de.hshannover.f4.trust.ifmapj.identifier.Device;
import de.hshannover.f4.trust.ifmapj.identifier.IpAddress;
import de.hshannover.f4.trust.ifmapj.messages.Requests;
import de.hshannover.f4.trust.ifmapj.messages.ResultItem;
import de.hshannover.f4.trust.ifmapj.messages.SearchRequest;
import de.hshannover.f4.trust.ifmapj.messages.SearchResult;

/**
 * The <code>Context</code> provides a collection of informations and objects of
 * the application environment. Components like a {@link Converter} which needs
 * more information for the mapping process can query the <code>Context</code>
 * for the needed information.
 *
 * @author Ralf Steuerwald
 *
 */
public class Context {

    private static final Logger LOGGER = Logger.getLogger(Context.class
            .getName());

    private SSRC mSsrc;
    private String mOpenVasServerId;

    public Context(SSRC ssrc, String openVasServerId) {
        this.mSsrc = ssrc;
        this.mOpenVasServerId = openVasServerId;
    }

    public String getIfmapPublisherId() {
        return mSsrc.getPublisherId();
    }

    /**
     * Searches the MAPS for a device identifier for the given IP address.
     *
     * @param ip
     *            the source IP address
     * @return the device identifier or <code>null</code> if nothing could be
     *         found
     */
    public Device getIfmapDeviceForIp(IpAddress ip) {
        SearchRequest req = Requests.createSearchReq();
        req.setMatchLinksFilter("meta:device-ip or meta:access-request-ip or meta:access-request-device");
        req.setMaxDepth(2);
        req.setStartIdentifier(ip);

        req.addNamespaceDeclaration(IfmapStrings.BASE_PREFIX,
                IfmapStrings.BASE_NS_URI);
        req.addNamespaceDeclaration(IfmapStrings.STD_METADATA_PREFIX,
                IfmapStrings.STD_METADATA_NS_URI);

        try {
            SearchResult result = mSsrc.search(req);
            if (result.getResultItems().size() >= 3) { // items: device, ip, and
                                                       // device-ip
                Device d = extractDeviceFromResultItems(result.getResultItems());
                return d;
            }
        } catch (IfmapErrorResult e) {
            LOGGER.warning("exception occured while searching for device: "
                    + e.getMessage());
        } catch (IfmapException e) {
            LOGGER.warning("exception occured while searching for device: "
                    + e.getMessage());
        }
        return null;
    }

    public String getOpenVasServerId() {
        return mOpenVasServerId;
    }

    /**
     * Pulls the device identifier from the given {@link ResultItem}.
     *
     * @param resultItems
     *            the device identifier or <code>null</code>
     * @return
     */
    private Device extractDeviceFromResultItems(List<ResultItem> resultItems) {
        for (ResultItem i : resultItems) {
            if (i.getIdentifier1() instanceof Device) {
                return (Device) i.getIdentifier1();
            }
            if (i.getIdentifier2() instanceof Device) {
                return (Device) i.getIdentifier2();
            }
        }
        return null;
    }

}

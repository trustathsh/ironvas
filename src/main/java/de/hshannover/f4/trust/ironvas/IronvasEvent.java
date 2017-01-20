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


package de.hshannover.f4.trust.ironvas;

import java.io.Serializable;
import java.util.Date;

/**
 * This class contains informations related to a vulnerability detected by
 * OpenVAS with direct access dedicated to the event stream mode.
 *
 * @author Marius Rohde
 *
 */
public class IronvasEvent implements Serializable{

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	/**
	 * 
	 */
	
	private final String mOid;
    private final String mName;
    private final float mCvssBase;
    private final RiskfactorLevel mRiskFactor;
    private final String mCve;
    private final String mBid;
    
    private final String mId;
    private Date mOpenvasTimestamp;
    private Date mIronvasTimestamp;
    
    private final String mSubnet;
    private final String mHost;
    private final String mPort;

    private final ThreatLevel mThreat;
    private final String mDescription;
    
    private final String mIfMapPublisherID;
    
    private final boolean mNewEventFlag;

   

    public IronvasEvent(String id, Date timestamp, String subnet, String host,
            String port, ThreatLevel threat, String description, String oid, String name, float cvssBase,
            RiskfactorLevel riskFactor, String cve, String bid, String ifMapPublisherID, boolean newEvent) {
        
    	this.mId = id;
        this.mSubnet = subnet;
        this.mHost = host;
        this.mPort = port;
        this.mThreat = threat;
        this.mDescription = description;
    	this.mOid = oid;
        this.mName = name;
        this.mCvssBase = cvssBase;
        this.mRiskFactor = riskFactor;
        this.mCve = cve;
        this.mBid = bid;
        this.mOpenvasTimestamp = new Date(timestamp.getTime());
        this.mIronvasTimestamp = new Date();
        this.mIfMapPublisherID = ifMapPublisherID;
        this.mNewEventFlag = newEvent;
    }
    


	public String getOid() {
		return mOid;
	}

	public String getName() {
		return mName;
	}

	public float getCvssBase() {
		return mCvssBase;
	}

	public RiskfactorLevel getRiskFactor() {
		return mRiskFactor;
	}

	public String getCve() {
		return mCve;
	}

	public String getBid() {
		return mBid;
	}

	public String getId() {
		return mId;
	}

	public Date getOpenvasTimestamp() {
		return mOpenvasTimestamp;
	}
	
	public Date getIronvasTimestamp() {
		return mIronvasTimestamp;
	}

	public String getSubnet() {
		return mSubnet;
	}

	public String getHost() {
		return mHost;
	}

	public String getPort() {
		return mPort;
	}

	public ThreatLevel getThreat() {
		return mThreat;
	}

	public String getDescription() {
		return mDescription;
	}
	
    public String getIfMapPublisherID() {
		return mIfMapPublisherID;
	}
    
    public boolean getNewEventFlag(){
    	return mNewEventFlag;
    }
	
}

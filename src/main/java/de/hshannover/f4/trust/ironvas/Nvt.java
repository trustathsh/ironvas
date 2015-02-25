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

/**
 * Represents the information of an OpenVAS network vulnerability test.
 *
 * @author Ralf Steuerwald
 *
 */
public class Nvt {

    private final String mOid;
    private final String mName;
    private final float mCvssBase;
    private final RiskfactorLevel mRiskFactor;
    private final String mCve;
    private final String mBid;

    public Nvt(String oid, String name, float cvssBase,
            RiskfactorLevel riskFactor, String cve, String bid) {
        super();
        this.mOid = oid;
        this.mName = name;
        this.mCvssBase = cvssBase;
        this.mRiskFactor = riskFactor;
        this.mCve = cve;
        this.mBid = bid;
    }

    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + (mBid == null ? 0 : mBid.hashCode());
        result = prime * result + (mCve == null ? 0 : mCve.hashCode());
        result = prime * result + Float.floatToIntBits(mCvssBase);
        result = prime * result + (mName == null ? 0 : mName.hashCode());
        result = prime * result + (mOid == null ? 0 : mOid.hashCode());
        result = prime * result
                + (mRiskFactor == null ? 0 : mRiskFactor.hashCode());
        return result;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
			return true;
		}
        if (obj == null) {
			return false;
		}
        if (getClass() != obj.getClass()) {
			return false;
		}
        Nvt other = (Nvt) obj;
        if (mBid == null) {
            if (other.mBid != null) {
				return false;
			}
        } else if (!mBid.equals(other.mBid)) {
			return false;
		}
        if (mCve == null) {
            if (other.mCve != null) {
				return false;
			}
        } else if (!mCve.equals(other.mCve)) {
			return false;
		}
        if (Float.floatToIntBits(mCvssBase) != Float
                .floatToIntBits(other.mCvssBase)) {
			return false;
		}
        if (mName == null) {
            if (other.mName != null) {
				return false;
			}
        } else if (!mName.equals(other.mName)) {
			return false;
		}
        if (mOid == null) {
            if (other.mOid != null) {
				return false;
			}
        } else if (!mOid.equals(other.mOid)) {
			return false;
		}
        if (mRiskFactor != other.mRiskFactor) {
			return false;
		}
        return true;
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

}

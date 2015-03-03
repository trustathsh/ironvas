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
 * This file is part of ironvas, version 0.1.5, implemented by the Trust@HsH
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;

import org.junit.Before;
import org.junit.Test;

public class NvtTest {

    private Nvt mN1Equalsn2;
    private Nvt mN2Equalsn1;
    private Nvt mN3;

    @Before
    public void setUp() {
        mN1Equalsn2 = new Nvt("1.3.6.1.4.1.25623.1.0.800615",
                "Cscope putstring Multiple Buffer Overflow vulnerability",
                9.3f, RiskfactorLevel.Critical, "CVE-2009-1577", "NOBID");
        mN2Equalsn1 = new Nvt("1.3.6.1.4.1.25623.1.0.800615",
                "Cscope putstring Multiple Buffer Overflow vulnerability",
                9.3f, RiskfactorLevel.Critical, "CVE-2009-1577", "NOBID");
        mN3 = new Nvt("3.3.6.1.4.1.25623.1.0.800615",
                "Cscope putstring Multiple Buffer Overflow vulnerability",
                9.3f, RiskfactorLevel.Critical, "CVE-2009-1577", "NOBID");
    }

    @Test
    public void testEquals() {
        assertEquals(mN1Equalsn2, mN2Equalsn1);
        assertFalse(mN1Equalsn2.equals(mN3));
    }

    @Test
    public void testHashCode() {
        assertEquals(mN1Equalsn2.hashCode(), mN2Equalsn1.hashCode());
        assertFalse(mN1Equalsn2.hashCode() == mN3.hashCode());
    }

    @Test
    public void testGetOid() {
        assertEquals("3.3.6.1.4.1.25623.1.0.800615", mN3.getOid());
    }

    @Test
    public void testGetName() {
        assertEquals("Cscope putstring Multiple Buffer Overflow vulnerability",
                mN3.getName());
    }

    @Test
    public void testGetCvssBase() {
        assertEquals(9.3f, mN3.getCvssBase(), 0.00001);
    }

    @Test
    public void testGetRiskFactor() {
        assertEquals(RiskfactorLevel.Critical, mN3.getRiskFactor());
    }

    @Test
    public void testGetCve() {
        assertEquals("CVE-2009-1577", mN3.getCve());
    }

    @Test
    public void testGetBid() {
        assertEquals("NOBID", mN3.getBid());
    }

}

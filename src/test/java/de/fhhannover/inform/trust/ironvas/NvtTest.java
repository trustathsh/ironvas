package de.fhhannover.inform.trust.ironvas;

/*
 * #%L
 * ====================================================
 *   _____                _     ____  _____ _   _ _   _
 *  |_   _|_ __ _   _ ___| |_  / __ \|  ___| | | | | | |
 *    | | | '__| | | / __| __|/ / _` | |_  | |_| | |_| |
 *    | | | |  | |_| \__ \ |_| | (_| |  _| |  _  |  _  |
 *    |_| |_|   \__,_|___/\__|\ \__,_|_|   |_| |_|_| |_|
 *                             \____/
 * 
 * =====================================================
 * 
 * Fachhochschule Hannover 
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.inform.fh-hannover.de/
 * 
 * This file is part of ironvas, version 0.1.1, implemented by the Trust@FHH 
 * research group at the Fachhochschule Hannover.
 * 
 * ironvas is a *highly experimental* integration of Open Vulnerability Assessment 
 * System (OpenVAS) into a MAP-Infrastructure. The integration aims to share security 
 * related informations (vulnerabilities detected by OpenVAS) with other network 
 * components in the TNC architecture via IF-MAP.
 * %%
 * Copyright (C) 2011 - 2013 Trust@FHH
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

import org.junit.Before;
import org.junit.Test;

import de.fhhannover.inform.trust.ironvas.Nvt;
import de.fhhannover.inform.trust.ironvas.RiskfactorLevel;
import static org.junit.Assert.*;

public class NvtTest {

    private Nvt n1Equalsn2;
    private Nvt n2Equalsn1;
    private Nvt n3;

    @Before
    public void setUp() {
        n1Equalsn2 = new Nvt("1.3.6.1.4.1.25623.1.0.800615",
                "Cscope putstring Multiple Buffer Overflow vulnerability",
                9.3f, RiskfactorLevel.Critical, "CVE-2009-1577", "NOBID");
        n2Equalsn1 = new Nvt("1.3.6.1.4.1.25623.1.0.800615",
                "Cscope putstring Multiple Buffer Overflow vulnerability",
                9.3f, RiskfactorLevel.Critical, "CVE-2009-1577", "NOBID");
        n3 = new Nvt("3.3.6.1.4.1.25623.1.0.800615",
                "Cscope putstring Multiple Buffer Overflow vulnerability",
                9.3f, RiskfactorLevel.Critical, "CVE-2009-1577", "NOBID");
    }

    @Test
    public void testEquals() {
        assertEquals(n1Equalsn2, n2Equalsn1);
        assertFalse(n1Equalsn2.equals(n3));
    }

    @Test
    public void testHashCode() {
        assertEquals(n1Equalsn2.hashCode(), n2Equalsn1.hashCode());
        assertFalse(n1Equalsn2.hashCode() == n3.hashCode());
    }

    @Test
    public void testGetOid() {
        assertEquals("3.3.6.1.4.1.25623.1.0.800615", n3.getOid());
    }

    @Test
    public void testGetName() {
        assertEquals("Cscope putstring Multiple Buffer Overflow vulnerability",
                n3.getName());
    }

    @Test
    public void testGetCvss_base() {
        assertEquals(9.3f, n3.getCvss_base(), 0.00001);
    }

    @Test
    public void testGetRisk_factor() {
        assertEquals(RiskfactorLevel.Critical, n3.getRisk_factor());
    }

    @Test
    public void testGetCve() {
        assertEquals("CVE-2009-1577", n3.getCve());
    }

    @Test
    public void testGetBid() {
        assertEquals("NOBID", n3.getBid());
    }

}

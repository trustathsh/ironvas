package de.fhhannover.inform.trust.ironvas;

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
		n1Equalsn2 = new Nvt(
				"1.3.6.1.4.1.25623.1.0.800615",
				"Cscope putstring Multiple Buffer Overflow vulnerability",
				9.3f,
				RiskfactorLevel.Critical,
				"CVE-2009-1577",
				"NOBID");
		n2Equalsn1 = new Nvt(
				"1.3.6.1.4.1.25623.1.0.800615",
				"Cscope putstring Multiple Buffer Overflow vulnerability",
				9.3f,
				RiskfactorLevel.Critical,
				"CVE-2009-1577",
				"NOBID");
		n3 = new Nvt(
				"3.3.6.1.4.1.25623.1.0.800615",
				"Cscope putstring Multiple Buffer Overflow vulnerability",
				9.3f,
				RiskfactorLevel.Critical,
				"CVE-2009-1577",
				"NOBID");
	}

	@Test
	public void testEquals() {
		assertEquals(n1Equalsn2, n2Equalsn1);
		assertFalse(n1Equalsn2.equals(n3));
	}
	
	public void testHashCode() {
		assertEquals(n1Equalsn2.hashCode(), n2Equalsn1.hashCode());
		assertFalse(n1Equalsn2.hashCode() == n3.hashCode());
	}
	
	
}

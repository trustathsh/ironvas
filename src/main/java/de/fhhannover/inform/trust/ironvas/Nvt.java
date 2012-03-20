package de.fhhannover.inform.trust.ironvas;

/**
 * Represents the information of an OpenVAS network vulnerability test.
 * 
 * @author Ralf Steuerwald
 *
 */
public class Nvt {
	
	private final String oid;
	private final String name;
	private final float cvss_base;
	private final RiskfactorLevel risk_factor;
	private final String cve;
	private final String bid;

	public Nvt(String oid, String name, float cvss_base,
			RiskfactorLevel risk_factor, String cve, String bid) {
		super();
		this.oid = oid;
		this.name = name;
		this.cvss_base = cvss_base;
		this.risk_factor = risk_factor;
		this.cve = cve;
		this.bid = bid;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((bid == null) ? 0 : bid.hashCode());
		result = prime * result + ((cve == null) ? 0 : cve.hashCode());
		result = prime * result + Float.floatToIntBits(cvss_base);
		result = prime * result + ((name == null) ? 0 : name.hashCode());
		result = prime * result + ((oid == null) ? 0 : oid.hashCode());
		result = prime * result
				+ ((risk_factor == null) ? 0 : risk_factor.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Nvt other = (Nvt) obj;
		if (bid == null) {
			if (other.bid != null)
				return false;
		} else if (!bid.equals(other.bid))
			return false;
		if (cve == null) {
			if (other.cve != null)
				return false;
		} else if (!cve.equals(other.cve))
			return false;
		if (Float.floatToIntBits(cvss_base) != Float
				.floatToIntBits(other.cvss_base))
			return false;
		if (name == null) {
			if (other.name != null)
				return false;
		} else if (!name.equals(other.name))
			return false;
		if (oid == null) {
			if (other.oid != null)
				return false;
		} else if (!oid.equals(other.oid))
			return false;
		if (risk_factor != other.risk_factor)
			return false;
		return true;
	}



	public String getOid() {
		return oid;
	}

	public String getName() {
		return name;
	}

	public float getCvss_base() {
		return cvss_base;
	}

	public RiskfactorLevel getRisk_factor() {
		return risk_factor;
	}

	public String getCve() {
		return cve;
	}

	public String getBid() {
		return bid;
	}
	
}
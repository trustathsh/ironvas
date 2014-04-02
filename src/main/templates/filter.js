importPackage(Packages.java.lang);
importPackage(Packages.de.hshannover.f4.trust.ironvas);

/* The 'filter'-Method gets called by ironvas, if it returns
 * false for the given vulnerability the vulnerability is
 * discarded from further processing.
 *
 * ThreatLevel.{Unknown, Debug, Log, Low, Medium, High}
 * RiskfactorLevel.{Unknown, None, Low, Medium, High, Critical}
 */
function filter(vulnerability) {
    return true; // default process all vulnerability
    //return filterByThreatLevel(vulnerability);
}


//*****************************************************************************

function filterByThreatLevel(vulnerability) {
    var minLevel = ThreatLevel.Low;

    if (vulnerability.getThreat().compareTo(minLevel) < 0) {
        return false;
    }
    else {
        return true;
    }
}

function filterByName(vulnerability) {
	var re = /Firefox/;

	if (vulnerability.getNvt().getName().match(re)) {
		return true;
	else
		return false;
}

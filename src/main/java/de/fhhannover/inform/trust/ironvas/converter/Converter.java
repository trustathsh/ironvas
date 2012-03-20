package de.fhhannover.inform.trust.ironvas.converter;

import java.util.List;
import java.util.Set;

import de.fhhannover.inform.trust.ifmapj.messages.PublishElement;
import de.fhhannover.inform.trust.ironvas.Vulnerability;

/**
 * A <code>Converter</code> is capable of mapping {@link Vulnerability}
 * instances to IF-MAP data structures for processing with <code>ifmapj</code>.
 * The implementation of this interface is free to choose if a
 * {@link Vulnerability} instance is mapped exact to one IF-MAP representation
 * (e.g. event) or if the information is distributed over more than one
 * representation (e.g. event and some special schema).
 * Furthermore the implementation of a <code>Converter</code> is free to
 * choose what kind of publish operation (update or notify) is executed.
 * <p>
 * Note that the transformation must be symmetric for updates and deletes. This
 * means that if one {@link Vulnerability} object is mapped to more than
 * one representation, the delete-mapping for the same {@link Vulnerability}
 * object must result in a complete delete operation for all previously
 * generated representation of that {@link Vulnerability}. 
 * 
 * @author Ralf Steuerwald
 *
 */
public interface Converter {
	
	public List<PublishElement> toUpdates(Set<Vulnerability> vulnerabilities);
	public List<PublishElement> toDeletes(Set<Vulnerability> vulnerabilities);

}

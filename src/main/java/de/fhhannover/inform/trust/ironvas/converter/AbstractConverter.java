package de.fhhannover.inform.trust.ironvas.converter;

public abstract class AbstractConverter implements Converter {

	protected String publisherId;
	protected String openVasServerId;
	
	public AbstractConverter(String publisherId, String openVasServerId) {
		this.publisherId = publisherId;
		this.openVasServerId = openVasServerId;
	}
}

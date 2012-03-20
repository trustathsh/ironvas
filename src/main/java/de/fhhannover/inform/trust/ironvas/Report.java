package de.fhhannover.inform.trust.ironvas;

import java.util.List;

/**
 * Simple POJO to store information related to a report of an OpenVAS
 * task.
 * 
 * @author Ralf Steuerwald
 *
 */
public class Report {
	
	public final String taskId;
	public final List<Vulnerability> vulnerabilities;
	
	public Report(String taskId, List<Vulnerability> vulnerabilities) {
		super();
		this.taskId = taskId;
		this.vulnerabilities = vulnerabilities;
	}
}

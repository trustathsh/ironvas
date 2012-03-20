package de.fhhannover.inform.trust.ironvas.omp

import scala.xml.Utility.trim
import scala.xml.Attribute
import scala.xml.Text
import scala.xml.Null
import scala.xml.Elem

/**
 * This object stores both XML tags and other constants of the OpenVAS
 * Management Protocol (OMP).
 * 
 * @see http://www.openvas.org/omp-2-0.html
 * 
 * @author Ralf Steuerwald
 */
object OmpProtocol {
    
    val statusOK = (200, "OK")
    
    def getVersion() = <get_version />
    
    def authenticate(username: String, password: String) = {
    	val xml = 	<authenticate>
    					<credentials>
    						<username>{username}</username>
    						<password>{password}</password>
    					</credentials>
    				</authenticate>
    	trim(xml)
    }
    
    def getTasks() = <get_tasks/>
        
    def getReports() = <get_reports/>
        
    def getReports(id: String) = <get_reports report_id={id} />
}

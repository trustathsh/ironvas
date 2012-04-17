/*
 * Project: ironvas
 * Package: main.scala.de.fhhannover.inform.trust.ironvas.omp
 * File:    OmpProtocol.scala
 *
 * Copyright (C) 2011-2012 Hochschule Hannover
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany 
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
    
    object Extensions {
        val parserError = (700, "Parser Error")
    }
    
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

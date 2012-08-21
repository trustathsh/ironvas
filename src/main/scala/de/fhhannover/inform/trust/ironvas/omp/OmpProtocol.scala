/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.omp
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

  def getVersion() = <get_version/>

  def authenticate(username: String, password: String) = {
    val xml = <authenticate>
                <credentials>
                  <username>{ username }</username>
                  <password>{ password }</password>
                </credentials>
              </authenticate>
    trim(xml)
  }

  def getTasks() = <get_tasks/>

  def getReports() = <get_reports/>

  def getReports(id: String) = <get_reports report_id={ id }/>

  def createTarget(name: String, host: String) = {
    val xml = <create_target>
                <name>{ name }</name>
                <hosts>{ host }</hosts>
              </create_target>
    trim(xml)
  }

  def deleteTarget(id: String) = <delete_target target_id={ id }/>

  def getTargets() = <get_targets tasks="1"/>

  def getConfigs() = <get_configs/>

  def createTask(name: String, configId: String, targetId: String) = {
    val xml = <create_task>
                <name>{ name }</name>
                <config id={ configId }/>
                <target id={ targetId }/>
              </create_task>
    trim(xml)
  }

  def deleteTask(id: String) = <delete_task task_id={ id }/>

  def startTask(id: String) = <start_task task_id={ id }/>

}

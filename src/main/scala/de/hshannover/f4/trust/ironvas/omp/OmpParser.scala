/*
 * #%L
 * =====================================================
 *   _____                _     ____  _   _       _   _
 *  |_   _|_ __ _   _ ___| |_  / __ \| | | | ___ | | | |
 *    | | | '__| | | / __| __|/ / _` | |_| |/ __|| |_| |
 *    | | | |  | |_| \__ \ |_| | (_| |  _  |\__ \|  _  |
 *    |_| |_|   \__,_|___/\__|\ \__,_|_| |_||___/|_| |_|
 *                             \____/
 * 
 * =====================================================
 * 
 * Hochschule Hannover
 * (University of Applied Sciences and Arts, Hannover)
 * Faculty IV, Dept. of Computer Science
 * Ricklinger Stadtweg 118, 30459 Hannover, Germany
 * 
 * Email: trust@f4-i.fh-hannover.de
 * Website: http://trust.f4.hs-hannover.de
 * 
 * This file is part of ironvas, version 0.1.7, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2011 - 2016 Trust@HsH
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
package de.hshannover.f4.trust.ironvas.omp

import java.util.Date
import java.util.GregorianCalendar
import scala.xml.Elem
import scala.xml.XML
import de.hshannover.f4.trust.ironvas.Nvt
import de.hshannover.f4.trust.ironvas.RiskfactorLevel
import de.hshannover.f4.trust.ironvas.ThreatLevel
import de.hshannover.f4.trust.ironvas.Vulnerability
import java.text.SimpleDateFormat
import java.util.Locale
import java.text.ParseException
import java.util.TimeZone

/**
 * <code>OmpParser</code> is capable of parsing the OpenVAS Management Protocol
 * (OMP).
 *
 * @author Ralf Steuerwald
 *
 */
class OmpParser {

  /* Reminder: The "\" method on scala.xml.NodeSeq returns an empty NodeSeq
   * if the requested element does not exists, the same holds for attributes.
   * Example:
   *     val xml = <foo><bar>hello world</bar></foo>
   *     (xml \ "baz").text == ""
   * This means that none of the method in this class will throw an exception
   * because of an non existing element/attribute.
   */

  /* OpenVAS uses C ctime format for dates.
   * Abbreviations for month are "Jan", "Feb", "Mar", "Apr", "May", "Jun",
   * "Jul", "Aug", "Sep", "Oct", "Nov", and "Dec".
   *
   * Example: "Wed Jun 30 21:49:08 1993"
   */
  val locale = Locale.ENGLISH
  val cDateFormat = new SimpleDateFormat("EEE MMM dd HH:mm:ss yyyy", locale)
  val parser = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
  parser.setTimeZone(TimeZone.getTimeZone("UTC"))

  def getVersionResponse(xml: Elem) = {
    val statusCode = status(xml)
    val version = (xml \ "version").text

    (statusCode, version)
  }

  def getVersionResponse(xmlString: String): ((Int, String), String) = {
    val xml = XML.loadString(xmlString)
    getVersionResponse(xml)
  }

  def authenticateResponse(xml: Elem) = {
    status(xml)
  }

  def authenticateResponse(xmlString: String): (Int, String) = {
    val xml = XML.loadString(xmlString)
    authenticateResponse(xml)
  }

  /**
   * Parse the response from a get_task request.
   *
   * @param xml the XML to parse
   * @return a tuple with status information and a sequence of tasks
   */
  def getTasksResponse(xml: Elem) = {
    val statusCode = status(xml)

    // iterate over all tasks elements in the document
    val tasks = for {
      task <- (xml \ "task")

      id = (task \ "@id").text
      name = (task \ "name").text
      taskStatus = (task \ "status").text
      lastReportId = (task \ "last_report" \ "report" \ "@id").text
    } yield Task(id, name, taskStatus,lastReportId)

    (statusCode, tasks)
  }

  def getTasksResponse(xmlString: String): ((Int, String), Seq[Task]) = {
    val xml = XML.loadString(xmlString)
    getTasksResponse(xml)
  }

  /**
   * Parse the response from a get_report request.
   *
   * @param xml the XML to parse
   * @return a tuple with status information and a sequence of vulnerabilities
   *         for each report that was fetched
   */
  def getReportsResponse(xml: Elem) = {
    val statusCode = status(xml)

    // iterate over all reports in the document
    val reports = for {
      report <- (xml \ "report" \ "report")

      results = report \ "results"

      // iterate over all results in the current report
      vulnerabilities = for {
        result <- (results \ "result")

        // get the text values of the vulnerability elements
        id = (result \ "@id").text
        date = (report \ "scan_end").text
        subnet = (result \ "subnet").text
        host = (result \ "host").text
        port = (result \ "port").text
        threatLevel = (result \ "threat").text
        description = (result \ "description").text

        nvt = (result \ "nvt")

        // get the text values of the nvt elements
        nvt_oid = (nvt \ "@oid").text
        nvt_name = (nvt \ "name").text
        nvt_cvss_base = (nvt \ "cvss_base").text
        nvt_risk_factor = (nvt \ "risk_factor").text
        nvt_cve = (nvt \ "cve").text
        nvt_bid = (nvt \ "bid").text

      } yield { // process the values and finally yield the current vulnerability
        val base = parseCvssBase(nvt_cvss_base)
        val risk = parseRiskFactorLevel(nvt_risk_factor)
        val dateParsed = parseDate(date)
        val threat = parseThreatLevel(threatLevel)

        val n = new Nvt(nvt_oid, nvt_name, base, risk, nvt_cve, nvt_bid)
        new Vulnerability(id, dateParsed, subnet, host, port, threat, description, n)
      }
    } yield (vulnerabilities) // yield the collected vulnerability list

    (statusCode, reports)
  }

  def getReportsResponse(xmlString: String): ((Int, String), Seq[Seq[Vulnerability]]) = {
    val xml = XML.loadString(xmlString)
    getReportsResponse(xml)
  }

  /**
   * Parse the status informations from a response.
   *
   * @param xml the XML to parse
   * @return a tuple with the status code an the status text
   */
  def status(xml: Elem) = {
    val status = (xml \ "@status").text
    val status_text = (xml \ "@status_text").text

    if (status == "" || status_text == "") {
      OmpProtocol.Extensions.parserError
    } else {
      (status.toInt, status_text)
    }
  }

  def status(xmlString: String): (Int, String) = {
    val xml = XML.loadString(xmlString)
    status(xml)
  }

  /**
   * Parse the response from a create_target request.
   *
   * @param xml the XML to parse
   * @return a tuple with status information and the id of the created target
   */
  def createTargetResponse(xml: Elem) = {
    val statusCode = status(xml)
    val targetId = (xml \ "@id").text

    (statusCode, targetId)
  }

  def createTargetResponse(xmlString: String): ((Int, String), String) = {
    val xml = XML.loadString(xmlString)
    createTargetResponse(xml)
  }

  /**
   * Parse the response from a get_targets request.
   *
   * @param xml the XML to parse
   * @return a tuple with status information and a sequence of targets
   */
  def getTargetsResponse(xml: Elem) = {
    val statusCode = status(xml)
    val targets = for {
      target <- (xml \ "target")

      id = (target \ "@id").text
      name = (target \ "name").text
      hosts = (target \ "hosts").text

      tasks = for {
        task <- (target \ "tasks" \ "task")
        id = (task \ "@id").text
        name = (task \ "name").text
      } yield Task(id, name, "","")

    } yield Target(id, name, hosts, tasks)

    (statusCode, targets)
  }

  def getTargetResponse(xmlString: String): ((Int, String), Seq[Target]) = {
    val xml = XML.loadString(xmlString)
    getTargetsResponse(xml)
  }

  /**
   * Parse the response from a get_configs request.
   *
   * @param xml the XML to parse
   * @return a tuple with status information and a sequence of configs
   */
  def getConfigsResponse(xml: Elem) = {
    val statusCode = status(xml)
    val configs = for {
      config <- (xml \ "config")
      id = (config \ "@id").text
      name = (config \ "name").text
    } yield Config(id, name)

    (statusCode, configs)
  }

  def getConfigsResponse(xmlString: String): ((Int, String), Seq[Config]) = {
    val xml = XML.loadString(xmlString)
    getConfigsResponse(xml)
  }

  /**
   * Parse the response from a create_task request.
   *
   * @return a tuple with status information and the task id of the created task
   */
  def createTaskResponse(xml: Elem) = {
    val statusCode = status(xml)
    val taskId = (xml \ "@id").text

    (statusCode, taskId)
  }

  def createTaskResponse(xmlString: String): ((Int, String), String) = {
    val xml = XML.loadString(xmlString)
    createTaskResponse(xml)
  }

  /**
   * Convert a <code>ctime</code> date string into a <code>Date</code> object.
   * The date string contains no time zone information, it is assumed that
   * the locale "ENGLISH" is valid for the input.
   *
   * If the parsing fails the method returns January 1, 1970, 00:00:00 GMT.
   *
   * @param dateString the date to parse
   * @return the <code>Date</code> object
   */
  def parseDate(dateString: String): Date = try {
    cDateFormat.parse(dateString)
  } catch {
    case e: ParseException => 
      try { parser.parse(dateString) }catch{
        case e: ParseException => new Date(0)
      }
  }

  /**
   * Parse a cvss_base string to a float number. If the string is empty or
   * "NONE" it is interpreted as <code>0.0f</code>.
   * If the string can't be parsed <code>-1.0f</code> is returned.
   *
   * @param cvssBase the string to parse
   * @return a float
   */
  def parseCvssBase(cvssBase: String) = {
    try {
      if (cvssBase == "None" || cvssBase == "") {
        0.0f
      } else {
        cvssBase.toFloat
      }
    } catch {
      case e: NumberFormatException => {
        -1.0f
      }
    }
  }

  def parseThreatLevel(level: String) = level match {
    case "High" => ThreatLevel.High
    case "Medium" => ThreatLevel.Medium
    case "Low" => ThreatLevel.Low
    case "Log" => ThreatLevel.Log
    case "Debug" => ThreatLevel.Debug
    case _ => ThreatLevel.Unknown
  }

  def parseRiskFactorLevel(level: String) = level match {
    case "Critical" => RiskfactorLevel.Critical
    case "High" => RiskfactorLevel.High
    case "Medium" => RiskfactorLevel.Medium
    case "Low" => RiskfactorLevel.Low
    case "None" => RiskfactorLevel.None
    case _ => RiskfactorLevel.Unknown
  }

}

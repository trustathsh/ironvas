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
 * This file is part of ironvas, version 0.1.4, implemented by the Trust@HsH
 * research group at the Hochschule Hannover.
 * %%
 * Copyright (C) 2011 - 2015 Trust@HsH
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

import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.io.OutputStreamWriter
import java.io.PrintWriter
import java.io.StringWriter
import java.net.Socket
import java.util.logging.Logger
import scala.util.control.Breaks.break
import scala.util.control.Breaks.breakable
import javax.net.ssl.SSLSocketFactory
import javax.xml.stream.XMLInputFactory
import javax.xml.stream.XMLOutputFactory
import javax.xml.stream.XMLStreamConstants
import de.hshannover.f4.trust.ironvas.Vulnerability
import java.io.IOException
import java.net.UnknownHostException

/**
 * Implements a connection to an OpenVAS server via the OpenVAS Management
 * Protocol (OMP).
 * An OMP connection is somewhat state-less in the sense that there is no
 * session id or something like that, but for the majority of commands the
 * connection has to be authenticated. To keep things simple each public
 * method named after an OMP command executes that command (including the
 * authentication) on the OpenVAS server and closes the connection. The
 * connection is always SSL secured.
 *
 * @see http://www.openvas.org/omp-2-0.html
 *
 * @author Ralf Steuerwald
 *
 * @constructor creates a new <code>OmpConnection</code>
 * @param host             the OMP server to connect to
 * @param port             the port to connect to
 * @param username         the user name used for authentication
 * @param password         the password used for authentication
 * @param keystorePath     the path from which the keystore will be loaded
 * @param keystorePassword the password for the keystore
 */
class OmpConnection(
  val host: String,
  val port: Int,
  val username: String,
  val password: String,
  keystorePath: String,
  keystorePassword: String) {

  require(host != null)
  require(port > 0)
  require(username != null)
  require(password != null)

  private val socketFactory = if (keystorePath == null || keystorePassword == null) {
    SSLSocketFactory.getDefault()
  } else {
    Security.initSslSocketFactory(keystorePath, keystorePassword)
  }

  private val logger = Logger.getLogger(getClass().getName())
  private val ompParser = new OmpParser

  /**
   * Creates a new OmpConnection instance with the system default security
   * properties.
   *
   * @param host     the OMP server to connect to
   * @param port     the port to connect to
   * @param username the user name used for authentication
   * @param password the password used for authentication
   */
  def this(host: String, port: Int, username: String, password: String) = {
    this(host, port, username, password, null, null)
  }

  /**
   * Sends the get_version request.
   *
   * @return a tuple with status and version information.
   */
  def getVersion(): ((Int, String), String) = {
    synchronized {
      val request = OmpProtocol.getVersion().toString
      val response = executeRequest(request, false)
      ompParser.getVersionResponse(response)
    }
  }

  /**
   * Sends the get_tasks request.
   *
   * @return a tuple with status information and a sequence of tasks
   */
  def getTasks(): ((Int, String), Seq[Task]) = {
    synchronized {
      val request = OmpProtocol.getTasks().toString
      val response = executeRequest(request)
      ompParser.getTasksResponse(response)
    }
  }

  /**
   * Sends the delete_target request for the given target id.
   *
   * @param id the target to delete
   * @returns a tuple with status informations
   */
  def deleteTarget(id: String): (Int, String) = {
    require(id != null)

    synchronized {
      val request = OmpProtocol.deleteTarget(id).toString
      val response = executeRequest(request)
      ompParser.status(response)
    }
  }

  /**
   * Sends the create_target request.
   *
   * @param name the name of the new target
   * @param host the host (list) for the new target
   * @returns a tuple with status information and the id of the created target
   */
  def createTarget(name: String, host: String): ((Int, String), String) = {
    require(name != null)
    require(host != null)

    synchronized {
      val request = OmpProtocol.createTarget(name, host).toString
      val response = executeRequest(request)
      ompParser.createTargetResponse(response)
    }
  }

  /**
   * Sends the get_targets request.
   *
   * @returns a tuple with status information and the list of targets
   */
  def getTargets(): ((Int, String), Seq[Target]) = {
    synchronized {
      val request = OmpProtocol.getTargets().toString
      val response = executeRequest(request)
      ompParser.getTargetResponse(response)
    }
  }

  /**
   * Sends the get_configs request.
   *
   * @return a tuple with status information and the list of configs
   */
  def getConfigs(): ((Int, String), Seq[Config]) = {
    synchronized {
      val request = OmpProtocol.getConfigs().toString
      val response = executeRequest(request)
      ompParser.getConfigsResponse(response)
    }
  }

  /**
   * Sends the get_reports request.
   *
   * @param id the id of the report to get, if not given all reports are fetched
   * @return a tuple with status information and a sequence of vulnerabilities
   *         for each report that was fetched
   */
  def getReports(id: String = ""): ((Int, String), Seq[Seq[Vulnerability]]) = {
    require(id != null)

    synchronized {
      val request = if (id == "") {
        OmpProtocol.getReports().toString
      } else {
        OmpProtocol.getReports(id).toString
      }
      val response = executeRequest(request)
      ompParser.getReportsResponse(response)
    }
  }

  /**
   * Sends the create_task request.
   *
   * @param name     the name of the new task
   * @param configId the id of the task configuration
   * @param targetId the id of the task target
   * @return a tuple with status information and the id of the created task
   */
  def createTask(name: String, configId: String, targetId: String): ((Int, String), String) = {
    require(name != null)
    require(configId != null)
    require(targetId != null)

    synchronized {
      val request = OmpProtocol.createTask(name, configId, targetId).toString
      val response = executeRequest(request)
      ompParser.createTaskResponse(response)
    }
  }

  /**
   * Sends the delete_task request.
   *
   * @param id the task id of the task to be deleted
   * @return a tuple with status information
   */
  def deleteTask(id: String): (Int, String) = {
    require(id != null)

    synchronized {
      val request = OmpProtocol.deleteTask(id).toString
      val response = executeRequest(request)
      ompParser.status(response)
    }
  }

  /**
   * Sends the start_task request.
   *
   * @param id the task id of the task to be started
   * @return a tuple with status information
   */
  def startTask(id: String): (Int, String) = {
    require(id != null)

    synchronized {
      val request = OmpProtocol.startTask(id).toString
      val response = executeRequest(request)
      ompParser.status(response)
    }
  }

  def getLatestReports(): Seq[(Task, Seq[Vulnerability])] = {
    synchronized {
      val getTasksRequest = OmpProtocol.getTasks().toString
      val getTaskResponse = executeRequest(getTasksRequest)
      val (_, tasks) = ompParser getTasksResponse getTaskResponse

      val tasksWithLastReport = tasks filter { _.lastReportId.length != 0 }

      val latestReports = for (task <- tasksWithLastReport) yield {
        val (_, reports) = getReports(task.lastReportId)
        (task, reports.head)
      }
      latestReports
    }
  }

  /**
   * Establish the TCP connection to the OMP server.
   *
   * @return a new <code>Connection</code> object
   * @throws IOException
   * @throws UnknownHostException
   */
  private def connect() = {
    val socket = socketFactory.createSocket(host, port)
    new Connection(
      socket.getInputStream(),
      socket.getOutputStream(),
      socket)
  }

  /**
   * Connects to the OMP server and sends the request string.
   * The request must contain only one command.
   * By default the authentication command is executed every time.
   * After executing the command the connection is closed.
   */
  private def executeRequest(request: String,
    withAuthentication: Boolean = true) = {
    logger.finer("sending request " + request)

    val connection = connect() // IOException, UnknownHostException
    if (withAuthentication) {
      val authRequest = OmpProtocol.authenticate(username, password).toString
      connection.output.print(authRequest)
      connection.output.flush()
      val authResponse = unblockResponse(connection) // FactoryConfigurationError, XMLStreamException, NoSuchElementException
      val status = ompParser.authenticateResponse(authResponse)

      if (status != OmpProtocol.statusOK) {
        throw new RuntimeException("OpenVAS authentication failed")
      }
    }
    connection.output.print(request)
    connection.output.flush()
    val response = unblockResponse(connection) // FactoryConfigurationError, XMLStreamException, NoSuchElementException

    val logresponse = if (response.length > 80) { response.substring(0, 80) + " ... [truncate]" } else { response }
    logger.finer("response is " + logresponse)
    connection.socket.close() // IOException
    response
  }

  /**
   * Avoid to block on the InputStream while reading the OMP response.
   * This method is capable of processing only one OMP response at once.
   *
   * @throws FactoryConfigurationError
   * @throws XMLStreamException
   * @throws NoSuchElementException
   */
  private def unblockResponse(connection: Connection) = {
    val buffer = new StringWriter()

    val inputFactory = XMLInputFactory.newInstance() // FactoryConfigurationError
    val outputFactory = XMLOutputFactory.newInstance() // FactoryConfigurationError
    val inputReader = inputFactory.createXMLEventReader(connection.input) // XMLStreamException
    val outputWriter = outputFactory.createXMLEventWriter(buffer) // XMLStreamException

    var firstElem: Option[String] = None
    breakable {
      while (inputReader.hasNext()) {
        val event = inputReader.nextEvent() // XMLStreamException, NoSuchElementException

        event.getEventType() match {
          case XMLStreamConstants.START_ELEMENT => {
            val startElement = event.asStartElement()
            outputWriter.add(startElement) // XMLStreamException
            if (firstElem == None) {
              firstElem = new Some(startElement.getName().toString())
            }
          }
          case XMLStreamConstants.END_ELEMENT => {
            val endElement = event.asEndElement()
            outputWriter.add(endElement) // XMLStreamException
            if (firstElem.getOrElse("").equals(endElement.getName().toString())) {
              break
            }
          }

          case XMLStreamConstants.CHARACTERS => {
            val characters = event.asCharacters()
            outputWriter.add(characters) // XMLStreamException
          }

          case XMLStreamConstants.START_DOCUMENT =>
            logger.finest("ignored START_DOCUMENT")

          case other =>
            throw new RuntimeException(
              "found unhandled constant %s in omp response".format(other))
        }
      }
    }
    buffer.toString()
  }

  private class Connection(i: InputStream, o: OutputStream, val socket: Socket) {
    val input = new BufferedReader(new InputStreamReader(i))
    val output = new PrintWriter(new OutputStreamWriter(o))
  }
}


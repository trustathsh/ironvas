package de.fhhannover.inform.trust.ironvas.omp

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
    
    
    private val socketFactory = if (keystorePath == null || keystorePassword == null) {
        SSLSocketFactory.getDefault()
    }
    else {
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
    def getVersion() = {
        val request = OmpProtocol.getVersion().toString
        val response = executeRequest(request, false)
        ompParser.getVersionResponse(response)
    }
    
    /**
     * Sends the get_tasks request.
     * 
     * @return a tuple with status information and a sequence of tasks
     */
    def getTasks() = {
        val request = OmpProtocol.getTasks().toString
        val response = executeRequest(request)
        ompParser.getTasksResponse(response)
    }
    
    /**
     * Sends the get_reports request.
     * 
     * @param id the id of the report to get, if not given all reports are fetched
     * @return a tuple with status information and a sequence of vulnerabilities
     *         for each report that was fetched
     */
    def getReports(id: String = "") = {
        val request = if (id == "") {
            OmpProtocol.getReports().toString
        }
        else {
            OmpProtocol.getReports(id).toString
        }
        val response = executeRequest(request)
        ompParser.getReportsResponse(response)
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
            withAuthentication: Boolean = true) = { // TODO handle exception and re-throw OmpException
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
	            
	            event.getEventType() match  {
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


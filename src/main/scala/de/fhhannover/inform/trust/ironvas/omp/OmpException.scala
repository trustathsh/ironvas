package de.fhhannover.inform.trust.ironvas.omp

/**
 * This class represents a failure in the processing of OMP.
 * 
 * @author Ralf Steuerwald
 * 
 * @constructor creates a new <code>OmpException</code>. The reason for the
 *              failure must be given as the message argument
 * @param message the reason for the failure
 * @param request the request (if any) that caused the failure
 * @param response the response (if any) that caused the failure
 * @param cause another exception that caused this
 */
class OmpException(
		message: String,
        val request: String = null,
        val response: String = null,
        cause: Throwable = null) extends Exception(message, cause) {
}
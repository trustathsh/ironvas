/*
 * Project: ironvas
 * Package: main.scala.de.fhhannover.inform.trust.ironvas.omp
 * File:    OmpException.scala
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

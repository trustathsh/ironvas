/*
 * Project: ironvas
 * Package: de.fhhannover.inform.trust.ironvas.omp
 * File:    Security.scala
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

import java.security.KeyStore
import java.security.SecureRandom

import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory

object Security {
    
    def initSslSocketFactory(path: String, pass: String) = {
        val trustManagers = {
            val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            val keystore = {
                val keystore = KeyStore.getInstance(KeyStore.getDefaultType())
                keystore.load(
                        getClass().getResourceAsStream(path), pass.toCharArray())
                keystore
            }
            factory.init(keystore)
            factory.getTrustManagers()
        }
        val context = SSLContext.getInstance("TLS")
        context.init(null, trustManagers, new SecureRandom)
        context.getSocketFactory()
    }
}

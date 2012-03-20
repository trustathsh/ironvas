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
import com.sap.gateway.ip.core.customdev.util.Message
import com.sap.it.api.ITApiFactory
import com.sap.it.api.keystore.KeystoreService
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.io.ByteArrayOutputStream
import java.util.Base64

def Message processData(Message message) {
    
    //Leemos el alias del key pair a descargar desde una property externalizada
    def alias = message.getProperty("KeyAlias")?.toString()
    if (!alias) {
        message.setBody("No se ha definido la property KeyAlias en la configuración del iflow.")
    }
    
    //Leemos la contraseña con la que protegeremos el key pair
    def password = message.getProperty("KeyPairPassword")?.toString()

    try {
        //Permitimos el acceso al al Key Store del tenant
        def service = ITApiFactory.getApi(KeystoreService.class, null)
        if (service == null)
            throw new Exception("Keystore no disponible.")

        //Nos traemos la clave privada y el certificado
        PrivateKey privateKey = service.getKey(alias)
        X509Certificate cert = service.getCertificate(alias)
        if (privateKey == null || cert == null)
            throw new Exception("Key pair no encontrado con alias " + alias)

        //Construimos un keystore que contenga el key pair en tiempo de ejecución
        KeyStore ks = KeyStore.getInstance("PKCS12")
        ks.load(null, null)
        ks.setKeyEntry(alias, privateKey, password.toCharArray(), [cert] as X509Certificate[])
        
        //Guardamos el key store como archivo (bytes)
        ByteArrayOutputStream keyStoreBytes = new ByteArrayOutputStream()
        ks.store(keyStoreBytes, password.toCharArray())
        byte[] pfxBytes = keyStoreBytes.toByteArray()

        //Para generar un attachment descargable es necesario codificar el archivo en base64
        def messageLog = messageLogFactory.getMessageLog(message)
        def base64Pfx;
        if (messageLog != null) {
            def filename = "${alias}_base64.txt"
            // Convierte el PFX a Base64
            base64Pfx = java.util.Base64.getEncoder().encodeToString(pfxBytes)
            // Agrega como attachment de texto
            messageLog.addAttachmentAsString(filename, base64Pfx, "text/plain")
        }

    } catch (Exception e) {
        message.setBody("Algo ha ido mal: " + e.toString())
    }

    return message
}

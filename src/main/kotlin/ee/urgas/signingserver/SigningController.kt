package ee.urgas.signingserver

import mu.KotlinLogging
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.client.RestTemplate
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

private val log = KotlinLogging.logger {}

@RestController
class SigningController {

    private final val signatureAlgorithm = "HmacSHA256"
    private final val keyBytes = "key".toByteArray(Charsets.UTF_8)
    private final val keySpec = SecretKeySpec(keyBytes, signatureAlgorithm)
    private final val mac = Mac.getInstance(signatureAlgorithm)

    init {
        mac.init(keySpec)
    }


    @GetMapping("/")
    fun sign(@RequestParam message: String): Response {

        val timestamp = System.currentTimeMillis() / 1000

        // include all message attributes
        val toBeSigned = message + timestamp

        val signatureBytes = mac.doFinal(toBeSigned.toByteArray(Charsets.UTF_8))
        val signatureString = bytesToHex(signatureBytes)

        val signedMessage = SignedMessage(message, timestamp, signatureString)

        log.info { signedMessage }

        val t = RestTemplate()
        val response: Response = t.postForObject("http://localhost:8082/", signedMessage, Response::class.java)!!

        log.info { response }
        return response
    }


    fun bytesToHex(byteArray: ByteArray) =
            byteArray.joinToString("") { String.format("%02x", (it.toInt() and 0xff)) }

}

data class SignedMessage(val message: String, val timestamp: Long, val signature: String)

data class Response(val status: String)

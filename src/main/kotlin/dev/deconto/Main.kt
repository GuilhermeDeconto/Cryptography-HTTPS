package dev.deconto

import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.abs

/* Full code execution output is as follows:
*
* T3 - Segurança de Sistemas
* Aluno: Guilherme Dall'Agnol Deconto
* a: 78229202513324640203383948911050967690556374666583189445530352392682597377261887909618512668247103766248595753399990588713756675798860877218282300744954892075710466620972447248389727958996402752546971
* A: 49902454806329643816801985827239186191172837835950544931575664434560769380770696423922244573418449562044140636037009377731490892181382030836533964305821075098667207586945101798587916371171469137189214997436898552371127643464986164047487874060716526541950007378683695919481667693659558038056234161692878077478
* A in HEX: 47103e8df21068b406c764a901b0173c1ff177eb7e34c23cc16415bcfd6b132dc0c3a00efb6f80ebd15e1cd8e0a7dd19b87dc6e84b370bb80645f9396d870bc7c9ebd5c0ecaf43de5daf1f971d0a710c63dbd0b09f4158bb28e4ca7705e227dc4956d680977d4b4cad231ac5442a31debe95e9a20a2996bfffc0f2f8bba07e26
* V: 40130462152853386931146634868554207743752556888599618953762938864739850151572467495068629098401548066674931221920830518053799728696032510390741613604305383188889643718656482679279256831449290796445142480696714288331018223225690147153621168113275252001036798830853475587933755242041413515537119822994844769034
* S: 0a111c1bd134167f4d87f0e8199da0c01c559258c3a3fb59c8fc058d8a1882ba
* ----=----=----=----=----=----=----=----=----=----=----=----
* Teacher message: Legal. Foste o primeiro a enviar. Agora devolve esta mensagem invertida e cifrada com a senha
* ----=----=----=----=----=----=----=----=----=----=----=----
* Reversed: ahnes a moc adarfic e aditrevni megasnem atse evloved arogA .raivne a oriemirp o etsoF .lageL
* ----=----=----=----=----=----=----=----=----=----=----=----
* 9a1bcb047fa3c399c688fd0223700a9e7718941aa9a9a6c2544f9512d3dce829474c27dd5ebbe22721db265dab60845f9840c339a5386439c424fa15d55d7e4d4fa0d877f7041a80579a8fbf971d5923c439881f8c30e2b5dd5d1736b9872d0598b3732bab8dd64f4288431e1de964d5
* ----=----=----=----=----=----=----=----=----=----=----=----
* Reversed: ahnes a moc adarfic e aditrevni megasnem atse evloved arogA .raivne a oriemirp o etsoF .lageL
* ----=----=----=----=----=----=----=----=----=----=----=----
* Perfeito. Agora comenta bem o codigo e submete. Coloca todo o exemplo no inicio do codigo como comentario
* ----=----=----=----=----=----=----=----=----=----=----=----
* 1f194867dc4643d5db11abc984661df039e55d448c8d7fbc2f2d915235a529afc930ab74a6ebe95ac66e315f92f5ba13322fe4a459880cebf500c2eb1ccfc14988d7a3884851c1eccd7af8d329657c3972c652ceb000f0a85f48d0edfb3dfd8831261002de940da21e5f45c718d6cb6b
* Reversed: Perfeito! Uma pergunta, o IV pode ser igual a mensagem anterior ou preciso gerar outro?
* ----=----=----=----=----=----=----=----=----=----=----=----
* Em geral deveria ser um diferente para cada mensagem para dificultar a vida do atacante
* ----=----=----=----=----=----=----=----=----=----=----=----
* b411c431833b593245e38340c068496ae54a6325a73fa37a581561473862c3d0271d30fce9985c38af7d499c31b16d52ca9c09711a19f54234b7c1a95bef0ee5b83137653fd56d3e792b0dedca4c1201e60ce1ec6efc9d87ed4e5d69fe0c560b8220178a9dc4950c3de9e682f9ab10ea67913ed17b6390ab8c31f03d489c1d56
* Reversed: Show! Entendi, vou gerar uma chave aleatoria para cada mensagem. Ao menos sei que esta funcionando, obrigado.
*
*/

fun main(args: Array<String>) {

    // Printing personal information
    println("T3 - Segurança de Sistemas")
    println("Aluno: Guilherme Dall'Agnol Deconto")

    // Method generateRandomLowerA() was only used once in order to discover the 'a' value and save it.
    // println(generateRandomLowerA())

    // Printing important info and values
    println("a: " + getLowerA())
    println("A: " + getUpperA())
    println("A in HEX: " + getUpperA().toString(16))
    println("V: " + getUpperV())
    println("S: " + getUpperS())

    println("----=----=----=----=----=----=----=----=----=----=----=----")

    // First message received from teacher
    val msg = "FC4E3A5DBD06B75FAF00E5D11A8DF25A22098EC4DFDD7BAE15D46B85FF6686B27580729E58CDD0F9D33D946FB7A931AFE6F744CA50D1CDA065A192642872C9F5F54D18DD055B55CA36AD52D1C3CBFD7C7FC7B13E156D356950575A666872A316F7968EFA5A045DDBB808F243942D7296"
    val teacherMsg = decryptCBC(msg, msg, getUpperS())
    println("Teacher message: $teacherMsg")

    println("----=----=----=----=----=----=----=----=----=----=----=----")

    // Reversing message and printing it
    val reversedMessage = teacherMsg.reversed()
    println("Reversed: $reversedMessage")

    println("----=----=----=----=----=----=----=----=----=----=----=----")

    // Encrypting reversed message and printing result
    val reversedMessageEncrypted = encryptCBC(convertStringToHex(reversedMessage), convertStringToHex(reversedMessage), getUpperS())
    println(reversedMessageEncrypted)

    println("----=----=----=----=----=----=----=----=----=----=----=----")

    // Decrypting encrypted message to test if everything is working as expected
    val reversedMessageEncryptedToDecrypt = "9a1bcb047fa3c399c688fd0223700a9e7718941aa9a9a6c2544f9512d3dce829474c27dd5ebbe22721db265dab60845f9840c339a5386439c424fa15d55d7e4d4fa0d877f7041a80579a8fbf971d5923c439881f8c30e2b5dd5d1736b9872d0598b3732bab8dd64f4288431e1de964d5"
    println("Reversed: " + decryptCBC(reversedMessageEncryptedToDecrypt, reversedMessageEncryptedToDecrypt, getUpperS()))

    println("----=----=----=----=----=----=----=----=----=----=----=----")

    // Decrypting teacher response to reversed message
    val msgFinalProf = "DEA9F51D3CC12B159D1A3983B1E4C9C0719EAEF80E1E8A07FB6423CC919AF4969D8ED676281056AD9AE353F3215E70494542B0A054C57A64EC70023082B5EC3A86E3745EF1AE52F4C4F7ADEE6418FC670319DB11278B3204D17C085F11319C494B69182E163D536F9C84CB41204F37E47F2F1B683CE4B31E82FBF9084027D426"
    println(decryptCBC(msgFinalProf, msgFinalProf, getUpperS()))

    println("----=----=----=----=----=----=----=----=----=----=----=----")

    val msgToTeacher = "Perfeito! Uma pergunta, o IV pode ser igual a mensagem anterior ou preciso gerar outro?"
    println(encryptCBC(convertStringToHex(msgToTeacher), convertStringToHex(msgToTeacher), getUpperS()))

    val msgToTeacherDecrypt = "1f194867dc4643d5db11abc984661df039e55d448c8d7fbc2f2d915235a529afc930ab74a6ebe95ac66e315f92f5ba13322fe4a459880cebf500c2eb1ccfc14988d7a3884851c1eccd7af8d329657c3972c652ceb000f0a85f48d0edfb3dfd8831261002de940da21e5f45c718d6cb6b"
    println("Reversed: " + decryptCBC(msgToTeacherDecrypt, msgToTeacherDecrypt, getUpperS()))

    println("----=----=----=----=----=----=----=----=----=----=----=----")

    val msgFromTeacherMyQuestion = "20EFB9819D430B3AC6675B099260E07E95328224666779DD700F3E9A5CC743B6C4617731471CA9BA80942AADAEB8CE2760B888AABEDC4E762C3F9EF724462BDD8E0811F7DB224A9BB30883827182D214844BA6F8770A841F2CD5CA91B2E5AFF2E46032EFDDE53ED71C553E9437DB5363"
    println(decryptCBC(msgFromTeacherMyQuestion, msgFromTeacherMyQuestion, getUpperS()))

    println("----=----=----=----=----=----=----=----=----=----=----=----")

    val msgToTeacher2 = "Show! Entendi, vou gerar uma chave aleatoria para cada mensagem. Ao menos sei que esta funcionando, obrigado."
    println(encryptCBC(convertStringToHex(msgToTeacher2), convertStringToHex(msgToTeacher2), getUpperS()))

    val msgToTeacherDecrypt2 = "b411c431833b593245e38340c068496ae54a6325a73fa37a581561473862c3d0271d30fce9985c38af7d499c31b16d52ca9c09711a19f54234b7c1a95bef0ee5b83137653fd56d3e792b0dedca4c1201e60ce1ec6efc9d87ed4e5d69fe0c560b8220178a9dc4950c3de9e682f9ab10ea67913ed17b6390ab8c31f03d489c1d56"
    println("Reversed: " + decryptCBC(msgToTeacherDecrypt2, msgToTeacherDecrypt2, getUpperS()))

}

fun generateRandomLowerA(size: Int = 200) : BigInteger {
    // Calculating a SecureRandom number with the size of 200 Bytes
    val random = SecureRandom()
    val bytes = ByteArray(202)
    random.nextBytes(bytes)

    val data = ArrayList<Int>()

    for (element in bytes){
        val number = abs(element.toInt())
        data.add(number % 10)
    }

    return data.joinToString("").toBigInteger()
}

fun getLowerA() : BigInteger {
    return "78229202513324640203383948911050967690556374666583189445530352392682597377261887909618512668247103766248595753399990588713756675798860877218282300744954892075710466620972447248389727958996402752546971".toBigInteger()
}

fun getLowerP() : BigInteger {
    return "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C69A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C013ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD7098488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708DF1FB2BC2E4A4371".toBigInteger(16)
}

fun getLowerG() : BigInteger {
    return "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507FD6406CFF14266D31266FEA1E5C41564B777E690F5504F213160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28AD662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24855E6EEB22B3B2E5".toBigInteger(16)
}

fun getUpperA() : BigInteger {
    return getModule(getLowerG(), getLowerA())
}

fun getUpperB() : BigInteger {
    return "1A20733EA06190EFA639F092FC22A9EB5BCA9CCA1A41AE4B3263D2C8F0907D709014D630F95FBF69B074A6FE7DC1E1A0B11B93CE7E8B9A41C6C67DD74EAA9A4833879251F3DD25246D104B1CC8928C2527F1A15147394CF21D572FBEB05F0D44E782F5AEC4ADF8DE68D252B8A2A848DC5DFBE7B2BDB8AE56AD123C9F12BC3900".toBigInteger(16)
}

fun getUpperV() : BigInteger {
    return getModule(getUpperB(), getLowerA())
}

fun getUpperS() : String {
    // Returning the hashed S
    return getUpperV().toString().sha256()
//    return hashString(getUpperV().toString(),"SHA-256")
}

fun getModule (g : BigInteger, a : BigInteger) : BigInteger {
    // Calculating the modPow of a BigInteger
    val p = getLowerP()
    return g.modPow(a, p)
}

fun String.sha256(): String {
    // Returning string result of "SHA-256"
    return hashString(this, "SHA-256")
}

private fun hashString(input: String, algorithm: String): String {
    return MessageDigest
        .getInstance(algorithm)
        .digest(input.toBigInteger().toByteArray())
        .fold("") { str, it -> str + "%02x".format(it) }
}

fun ByteArray.toHexString() : String {
    // Converting byte[] to hex string
    return this.joinToString("") { "%02x".format(it) }
}

fun encryptCBC(toEncrypt: String, secretIV: String, secretKey: String): String {

    // First step, converting all hex entries to byte[]
    val encryptedByteArray = hexStringToByteArray(toEncrypt)

    // For academic purposes I'm using the same IV, however in real world consider creating a new random IV
    // for example:
    // val secretIvByteArray = hexStringToByteArray(generateRandomLowerA(202).toString(16))
    // this will generate a random BigInteger and convert to hex in order to get the byte array
    val secretIvByteArray = hexStringToByteArray(secretIV.uppercase())
    val secretKeyByteArray = hexStringToByteArray(secretKey.uppercase())

    // Second step, initializing the variables following the exercise description
    val iv = IvParameterSpec(secretIvByteArray.copyOfRange(0, 16))
    val keySpec = SecretKeySpec(secretKeyByteArray.copyOfRange(0, 16), "AES")

    // Third step, initializing the AES/CBC/PKCS5Padding Cipher and encrypting the unencrypted message.
    val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")
    cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv)
    val byteArrayFinal = secretKeyByteArray.copyOfRange(0, 16) + encryptedByteArray
    val crypted = cipher.doFinal(byteArrayFinal)

    // Returning encrypted message in hex format
    return crypted.toHexString()
}

fun decryptCBC(encrypted : String, secretIV : String, secretKey : String): String {

    // First step, converting all hex entries to byte[]
    val encryptedByteArray = hexStringToByteArray(encrypted)
    val secretIvByteArray = hexStringToByteArray(secretIV.uppercase())
    val secretKeyByteArray = hexStringToByteArray(secretKey.uppercase())

    // Second step, initializing the variables following the exercise description
    // For the message I'm getting all the values starting at index 16
    // For the IV I'm getting the 16 first bytes (128 bits)
    // And for the keySpec I'm constructing the secret key with the first 128 bits of secret key byte[] with AES algorithm.
    val decodedByte: ByteArray = encryptedByteArray.copyOfRange(16, encryptedByteArray.size)
    val iv = IvParameterSpec(secretIvByteArray.copyOfRange(0, 16))
    val keySpec = SecretKeySpec(secretKeyByteArray.copyOfRange(0, 16), "AES")

    // Third step, initializing the AES/CBC/PKCS5Padding Cipher and decrypting the received encrypted message.
    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    cipher.init(Cipher.DECRYPT_MODE, keySpec, iv)
    val output = cipher.doFinal(decodedByte)

    // Returning decrypted message
    return String(output)
}

/*
* Method responsible for converting Hexadecimal String to byte[].
* This method loops through the string input and get the char corresponding
* to the Hex and then converts the result to byte.
*/
private fun hexStringToByteArray(s: String): ByteArray {
    val len = s.length
    val data = ByteArray(len / 2)
    var i = 0
    while (i < len) {
        data[i / 2] = ((Character.digit(s[i], 16) shl 4) +
                Character.digit(s[i + 1], 16)).toByte()
        i += 2
    }
    return data
}

/*
* Method responsible for converting any String to Hex.
*/
fun convertStringToHex(str: String): String {
    val hex = StringBuffer()

    // loop chars one by one
    for (temp in str.toCharArray()) {

        // convert char to int, for char `a` decimal 97
        val decimal = temp.code

        // convert int to hex, for decimal 97 hex 61
        hex.append(Integer.toHexString(decimal))
    }
    return hex.toString()
}
package com.daxue;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ser.Serializers;
import com.sun.xml.internal.messaging.saaj.packaging.mime.util.BASE64DecoderStream;
import org.junit.Test;
import sun.misc.BASE64Decoder;

import java.io.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.Assert.assertNotNull;

/**
 * 2018/5/30
 * <p>
 * OAuth0  jwt
 *
 * @author Shengzhao Li
 */
public class Auth0JwtTest {


    /**
     * Test JWT
     *
     * @throws Exception Exception
     */
    @Test
    public void jwt() throws Exception {

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        //读取文件字符串
        String publicKeyString = fromFileGetString("public_key.pem");
        publicKeyString = publicKeyString.replaceAll("-----(.*)-----(\r\n?|\n|)([\\s\\S]*)(\r\n?|\n|)-----(.*)-----", "$3");
        publicKeyString = publicKeyString.replace("\n", "");
        publicKeyString = publicKeyString.replace(" ", "");

        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyString));
        PublicKey pubKey = keyFactory.generatePublic(publicKeySpec);
        RSAPublicKey rsaPublicKey = (RSAPublicKey) pubKey;

        String priString = fromFileGetString("private_key.pem");
        priString = priString.replaceAll("-----(.*)-----(\r\n?|\n|)([\\s\\S]*)(\r\n?|\n|)-----(.*)-----", "$3");
        priString = priString.replace("\n", "");
        priString = priString.replace(" ", "");


        PKCS8EncodedKeySpec priKey = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(priString));
        RSAPrivateKey rsaPriLicKey = (RSAPrivateKey) keyFactory.generatePrivate(priKey);


        // RSA keyPair Generator
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        /*
         * 长度 至少 1024, 建议 2048
         */
        final int keySize = 2048;
        keyPairGenerator.initialize(keySize);

        final KeyPair keyPair = keyPairGenerator.genKeyPair();


        final PublicKey publicKey = keyPair.getPublic();
        final PrivateKey privateKey = keyPair.getPrivate();



        // gen id_token
        final Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) publicKey, (RSAPrivateKey) privateKey);

        final String idToken = JWT.create().withJWTId("jwt-id").withAudience("audience").withSubject("subject").sign(algorithm);

        assertNotNull(idToken);
        System.out.println(idToken);


        //verify
//        final DecodedJWT decodedJWT = JWT.decode(idToken);
//        System.out.println("id_token -> header: " + decodedJWT.getHeader());
//        System.out.println("id_token -> payload: " + decodedJWT.getPayload());
//        System.out.println("id_token -> token: " + decodedJWT.getToken());
//        System.out.println("id_token -> signature: " + decodedJWT.getSignature());


        final JWTVerifier verifier = JWT.require(algorithm).build();
        final DecodedJWT verify = verifier.verify(idToken);

        assertNotNull(verify);
        System.out.println(verify);


//        final Algorithm none = Algorithm.none();

    }

//    private byte[] genPublic(final String publicKeyString) {
//
//        final BaseEncoding BASE64 = Base64Encoding("base64()", "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/", '=');
//
//
//
//
//
//        return new byte[0];
//    }


    public String fromFileGetString(String fileName) {

        InputStream resourceAsStream = this.getClass().getClassLoader().getResourceAsStream(fileName);
        String result = "";
        try {
            StringBuilder stringBuilder = new StringBuilder();
            BufferedReader br = new BufferedReader(new InputStreamReader(resourceAsStream));

            String s;
            while((s = br.readLine()) != null) {
                stringBuilder.append(s);
            }

            br.close();
            result = stringBuilder.toString();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return result;
    }


}
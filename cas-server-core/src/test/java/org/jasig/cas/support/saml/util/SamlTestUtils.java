package org.jasig.cas.support.saml.util;

import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.util.zip.DeflaterOutputStream;

public class SamlTestUtils {
    public static void saveFile(String filename, String contents) {
        PrintWriter writer = null;
        try {
            writer = new PrintWriter(filename, "UTF-8");
        } catch (FileNotFoundException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();  //To change body of catch statement use File | Settings | File Templates.
        }
        writer.println(contents);
        writer.close();
    }

    public static String encodeMessage(final String xmlString) throws IOException {
        byte[] xmlBytes = xmlString.getBytes("UTF-8");
        ByteArrayOutputStream byteOutputStream = new ByteArrayOutputStream();
        DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(
                byteOutputStream);
        deflaterOutputStream.write(xmlBytes, 0, xmlBytes.length);
        deflaterOutputStream.close();

        // next, base64 encode it
        Base64 base64Encoder = new Base64();
        byte[] base64EncodedByteArray = base64Encoder.encode(byteOutputStream
                .toByteArray());
        return new String(base64EncodedByteArray);
    }
}
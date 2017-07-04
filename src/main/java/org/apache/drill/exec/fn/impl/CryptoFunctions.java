/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * <p/>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p/>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.drill.exec.fn.impl;

import io.netty.buffer.DrillBuf;
import org.apache.drill.exec.expr.DrillSimpleFunc;
import org.apache.drill.exec.expr.annotations.FunctionTemplate;
import org.apache.drill.exec.expr.annotations.Output;
import org.apache.drill.exec.expr.annotations.Param;
import org.apache.drill.exec.expr.annotations.Workspace;
import org.apache.drill.exec.expr.holders.VarCharHolder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;

public class CryptoFunctions{
    static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(CryptoFunctions.class);

    private CryptoFunctions() {}

    @FunctionTemplate(
        name = "md5",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class md5Function implements DrillSimpleFunc {

        @Param
        VarCharHolder raw_input;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Workspace
        java.security.MessageDigest md;

        @Override
        public void setup() {
            try {
                md = java.security.MessageDigest.getInstance("MD5");
            } catch( Exception e ) {
            }
        }

        @Override
        public void eval() {

            String input = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(raw_input.start, raw_input.end, raw_input.buffer);
            byte[] thedigest = null;
            String output_string = "";

            try {
                byte[] bytesOfMessage = input.getBytes("UTF-8");
                thedigest = md.digest(bytesOfMessage);
                output_string = String.format("%032X", new java.math.BigInteger(1, thedigest));
                output_string = output_string.toLowerCase();

            } catch( Exception e ) {
            }
            out.buffer = buffer;
            out.start = 0;
            out.end = output_string.getBytes().length;
            buffer.setBytes(0, output_string.getBytes());
        }

    }


    @FunctionTemplate(
        names = {"sha", "sha1"},
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class sha1Function implements DrillSimpleFunc {

        @Param
        VarCharHolder raw_input;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Override
        public void setup() {

        }

        @Override
        public void eval() {

            String input = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(raw_input.start, raw_input.end, raw_input.buffer);

            String sha1 = org.apache.commons.codec.digest.DigestUtils.sha1Hex(input);

            out.buffer = buffer;
            out.start = 0;
            out.end = sha1.getBytes().length;
            buffer.setBytes(0, sha1.getBytes());
        }

    }

    @FunctionTemplate(
        names = {"sha256", "sha2"},
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class sha256Function implements DrillSimpleFunc {

        @Param
        VarCharHolder raw_input;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;


        @Override
        public void setup() {

        }

        @Override
        public void eval() {

            String input = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(raw_input.start, raw_input.end, raw_input.buffer);

            String sha2 = org.apache.commons.codec.digest.DigestUtils.sha256Hex(input);

            out.buffer = buffer;
            out.start = 0;
            out.end = sha2.getBytes().length;
            buffer.setBytes(0, sha2.getBytes());
        }

    }

    @FunctionTemplate(
        name = "sha384",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class sha384Function implements DrillSimpleFunc {

        @Param
        VarCharHolder raw_input;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Override
        public void setup() {

        }

        @Override
        public void eval() {

            String input = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(raw_input.start, raw_input.end, raw_input.buffer);

            String sha384 = org.apache.commons.codec.digest.DigestUtils.sha384Hex(input);

            out.buffer = buffer;
            out.start = 0;
            out.end = sha384.getBytes().length;
            buffer.setBytes(0, sha384.getBytes());
        }

    }

    @FunctionTemplate(
        name = "sha512",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class sha512Function implements DrillSimpleFunc {

        @Param
        VarCharHolder raw_input;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Override
        public void setup() {

        }

        @Override
        public void eval() {

            String input = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(raw_input.start, raw_input.end, raw_input.buffer);

            String sha512 = org.apache.commons.codec.digest.DigestUtils.sha512Hex(input);

            out.buffer = buffer;
            out.start = 0;
            out.end = sha512.getBytes().length;
            buffer.setBytes(0, sha512.getBytes());
        }

    }

    @FunctionTemplate(
        name = "aes_encrypt",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class AESEncryptFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder rawInput;

        @Param
        VarCharHolder rawKey;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Workspace
        String key;

        @Workspace
        SecretKeySpec secretKey;

        @Workspace
        byte[] keyByteArray;

        @Workspace
        Cipher cipher;

        public void setup() {
            key = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(rawKey.start, rawKey.end, rawKey.buffer);
            java.security.MessageDigest sha = null;
            try {
                keyByteArray = key.getBytes("UTF-8");
                sha = java.security.MessageDigest.getInstance("SHA-1");
                keyByteArray = sha.digest(keyByteArray);
                keyByteArray = java.util.Arrays.copyOf(keyByteArray, 16);
                secretKey = new SecretKeySpec(keyByteArray, "AES");

                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }

        public void eval() {

            String input = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(rawInput.start, rawInput.end, rawInput.buffer);
            String encryptedText = "";
            try {
                encryptedText = javax.xml.bind.DatatypeConverter.printBase64Binary(cipher.doFinal(input.getBytes("UTF-8")));
            } catch ( Exception e ) {

            }

            out.buffer = buffer;
            out.start = 0;
            out.end = encryptedText.getBytes().length;
            buffer.setBytes(0, encryptedText.getBytes());
        }

    }

    @FunctionTemplate(
        name = "aes_decrypt",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class AESDecryptFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder rawInput;

        @Param
        VarCharHolder rawKey;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Workspace
        String key;

        @Workspace
        SecretKeySpec secretKey;

        @Workspace
        byte[] keyByteArray;

        @Workspace
        Cipher cipher;

        public void setup() {
            key = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(rawKey.start, rawKey.end, rawKey.buffer);
            java.security.MessageDigest sha = null;
            try {
                keyByteArray = key.getBytes("UTF-8");
                sha = java.security.MessageDigest.getInstance("SHA-1");
                keyByteArray = sha.digest(keyByteArray);
                keyByteArray = java.util.Arrays.copyOf(keyByteArray, 16);
                secretKey = new SecretKeySpec(keyByteArray, "AES");

                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            }
            catch (Exception e) {
                e.printStackTrace();
            }
        }
        @Override
        public void eval() {

            String input = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(rawInput.start, rawInput.end, rawInput.buffer);
            String decryptedText = "";
            try {
                decryptedText = new String( cipher.doFinal(javax.xml.bind.DatatypeConverter.parseBase64Binary(input)));
            } catch( Exception e){

            }

            out.buffer = buffer;
            out.start = 0;
            out.end = decryptedText.getBytes().length;
            buffer.setBytes(0, decryptedText.getBytes());
        }

    }

    @FunctionTemplate(
        name = "des_encrypt",
        scope = FunctionTemplate.FunctionScope.SIMPLE,
        nulls = FunctionTemplate.NullHandling.NULL_IF_NULL
    )
    public static class desEncryptFunction implements DrillSimpleFunc {

        @Param
        VarCharHolder raw_input;

        @Param
        VarCharHolder raw_key;

        @Output
        VarCharHolder out;

        @Inject
        DrillBuf buffer;

        @Workspace
        KeyGenerator keygenerator;

        @Workspace
        SecretKey myDesKey;

        @Workspace
        Cipher desCipher;

        public void setup() {

            try {
                String keyString = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(raw_key.start, raw_key.end, raw_key.buffer);

                byte[] keyBytes = javax.xml.bind.DatatypeConverter.parseHexBinary(keyString);

                javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("DES");
                myDesKey = factory.generateSecret(new javax.crypto.spec.DESKeySpec(keyBytes));

                // Create the cipher
                desCipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

                // Initialize the cipher for encryption
                desCipher.init(Cipher.ENCRYPT_MODE, myDesKey);

            } catch(Exception e) {
                e.printStackTrace();
            }

        }


        public void eval() {

            String input = org.apache.drill.exec.expr.fn.impl.StringFunctionHelpers.toStringFromUTF8(raw_input.start, raw_input.end, raw_input.buffer);
            String output = "";
            byte[] textEncrypted = new byte[10];
            try{
                //sensitive information
                byte[] text = input.getBytes();

                // Encrypt the text
                textEncrypted = desCipher.doFinal(text);
                output = textEncrypted.toString();

            }catch(Exception e){
                e.printStackTrace();
            }

            out.buffer = buffer;
            out.start = 0;
            out.end = output.getBytes().length;
            buffer.setBytes(0, output.getBytes());
        }

    }

}
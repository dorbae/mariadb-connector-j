/*
MariaDB Client for Java

Copyright (c) 2012-2014 Monty Program Ab.

This library is free software; you can redistribute it and/or modify it under
the terms of the GNU Lesser General Public License as published by the Free
Software Foundation; either version 2.1 of the License, or (at your option)
any later version.

This library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
for more details.

You should have received a copy of the GNU Lesser General Public License along
with this library; if not, write to Monty Program Ab info@montyprogram.com.

This particular MariaDB Client for Java file is work
derived from a Drizzle-JDBC. Drizzle-JDBC file which is covered by subject to
the following copyright and notice provisions:

Copyright (c) 2009-2011, Marcus Eriksson , Stephane Giron

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:
Redistributions of source code must retain the above copyright notice, this list
of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright notice, this
list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

Neither the name of the driver nor the names of its contributors may not be
used to endorse or promote products derived from this software without specific
prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS  AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
OF SUCH DAMAGE.
*/

package org.mariadb.jdbc.internal.com.send;

import org.mariadb.jdbc.internal.com.read.Buffer;
import org.mariadb.jdbc.internal.com.read.ErrorPacket;
import org.mariadb.jdbc.internal.io.input.PacketInputStream;
import org.mariadb.jdbc.internal.io.output.PacketOutputStream;
import org.mariadb.jdbc.internal.util.Options;

import javax.crypto.Cipher;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;
import java.util.Arrays;

import static org.mariadb.jdbc.internal.com.Packet.ERROR;

public class SendSha256PasswordAuthPacket extends AbstractAuthSwitchSendResponsePacket implements InterfaceAuthSwitchSendResponsePacket {

    private Options options;
    private PacketInputStream reader;

    /**
     * Constructor of SendSha256PasswordAuthPacket.
     *
     * @param password                  password
     * @param authData                  authData
     * @param packSeq                   packet sequence
     * @param passwordCharacterEncoding password charset
     * @param options                   connection options
     * @param reader                    input stream
     */
    public SendSha256PasswordAuthPacket(String password, byte[] authData, int packSeq, String passwordCharacterEncoding,
                                        Options options, PacketInputStream reader) {
        super(packSeq, authData, password, passwordCharacterEncoding);
        this.options = options;
        this.reader = reader;
    }

    /**
     * Send SHA256 password stream.
     *
     * @param pos database socket
     * @throws IOException if a connection error occur
     */
    public void send(PacketOutputStream pos) throws IOException, SQLException {
        if (password == null || password.equals("")) {
            pos.writeEmptyPacket(packSeq);
            return;
        }

        if (options.useSsl) {
            //can send plain text pwd
            pos.startPacket(packSeq);
            byte[] bytePwd;
            if (passwordCharacterEncoding != null && !passwordCharacterEncoding.isEmpty()) {
                bytePwd = password.getBytes(passwordCharacterEncoding);
            } else {
                bytePwd = password.getBytes();
            }
            pos.write(bytePwd);
            pos.write(0);
            pos.flush();
        } else {
            PublicKey publicKey;
            if (options.serverRsaPublicKeyFile != null && !options.serverRsaPublicKeyFile.isEmpty()) {
                publicKey = readPublicKeyFromFile(options.serverRsaPublicKeyFile);
            } else {
                //TODO add allowPublicKeyRetrieval option

                //ask public Key Retrieval
                pos.startPacket(packSeq++);
                pos.write((byte) 1);
                pos.flush();

                publicKey = readPublicKeyFromSocket();

            }

            byte[] seed;
            if (authData.length > 0) {
                //Seed is ended with a null byte value.
                seed = Arrays.copyOfRange(authData, 0, authData.length - 1);
            } else {
                seed = new byte[0];
            }

            byte[] bytePwd;
            if (passwordCharacterEncoding != null && !passwordCharacterEncoding.isEmpty()) {
                bytePwd = password.getBytes(passwordCharacterEncoding);
            } else {
                bytePwd = password.getBytes();
            }

            byte[] nullFinishedPwd = Arrays.copyOf(bytePwd, bytePwd.length + 1);
            byte[] xorBytes = new byte[nullFinishedPwd.length];
            int seedLength = seed.length;

            for (int i = 0; i < xorBytes.length; i++) {
                xorBytes[i] = (byte) (nullFinishedPwd[i] ^ seed[i % seedLength]);
            }

            try {

                Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, publicKey);

                byte[] cipherBytes = cipher.doFinal(xorBytes);
                pos.startPacket(packSeq++);
                pos.write(cipherBytes);
                pos.flush();

            } catch (Exception ex) {
                throw new SQLException("Could not connect using SHA256 plugin : " + ex.getMessage(), "S1009", ex);
            }
        }
    }

    private PublicKey readPublicKeyFromFile(String path) throws SQLException, IOException {
        try {
            byte[] keyBytes = Files.readAllBytes(Paths.get(options.serverRsaPublicKeyFile));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);

        } catch (Exception ex) {
            throw new SQLException("Could read server RSA public key from path " + path, "S1009", ex);
        }
    }

    private PublicKey readPublicKeyFromSocket() throws SQLException, IOException {
        Buffer buffer = reader.getPacket(true);
        if (buffer.getByteAt(0) == ERROR) {
            ErrorPacket ep = new ErrorPacket(buffer);
            String message = ep.getMessage();
            throw new SQLException("Could not connect: " + message, ep.getSqlState(), ep.getErrorNumber());
        }


        try {
            //read key
            byte[] keyBytes = buffer.readBytesNullEnd();
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } catch (Exception ex) {
            throw new SQLException("Could read server RSA public key: " + ex.getMessage(), "S1009", ex);
        }

    }
}

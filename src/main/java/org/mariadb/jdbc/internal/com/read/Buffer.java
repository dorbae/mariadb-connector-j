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

Copyright (c) 2009-2011, Marcus Eriksson

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

package org.mariadb.jdbc.internal.com.read;


import java.nio.charset.Charset;

public class Buffer {

    public byte[] buf;
    public int position;
    public int limit;

    public Buffer(final byte[] buf, int limit) {
        this.buf = buf;
        this.limit = limit;
    }

    /**
     * Constructor with default limit and offset.
     * @param buf byte array
     */
    public Buffer(final byte[] buf) {
        this.buf = buf;
        this.limit = this.buf.length;
    }

    public int remaining() {
        return limit - position;
    }

    /**
     * Reads a string from the buffer, looks for a 0 to end the string.
     *
     * @param charset the charset to use, for example ASCII
     * @return the read string
     */
    public String readString(final Charset charset) {
        byte ch;
        int cnt = 0;
        final byte[] byteArrBuff = new byte[remaining()];
        while (remaining() > 0 && ((ch = buf[position++]) != 0)) {
            byteArrBuff[cnt++] = ch;
        }
        return new String(byteArrBuff, 0, cnt, charset);
    }

    /**
     * Read a short (2 bytes) from the buffer.
     *
     * @return an short
     */
    public short readShort() {
        return (short) ((buf[position++] & 0xff)
                + ((buf[position++] & 0xff) << 8));
    }

    /**
     * Read 24 bit integer.
     *
     * @return length
     */
    public int read24bitword() {
        return (buf[position++] & 0xff)
                + ((buf[position++] & 0xff) << 8)
                + ((buf[position++] & 0xff) << 16);
    }

    /**
     * Read a int (4 bytes) from the buffer.
     *
     * @return a int
     */
    public int readInt() {
        return ((buf[position++] & 0xff)
                + ((buf[position++] & 0xff) << 8)
                + ((buf[position++] & 0xff) << 16)
                + ((buf[position++] & 0xff) << 24));
    }

    /**
     * Read a long (8 bytes) from the buffer.
     *
     * @return a long
     */
    public long readLong() {
        return ((buf[position++] & 0xff)
                + ((long) (buf[position++] & 0xff) << 8)
                + ((long) (buf[position++] & 0xff) << 16)
                + ((long) (buf[position++] & 0xff) << 24)
                + ((long) (buf[position++] & 0xff) << 32)
                + ((long) (buf[position++] & 0xff) << 40)
                + ((long) (buf[position++] & 0xff) << 48)
                + ((long) (buf[position++] & 0xff) << 56));
    }

    /**
     * Reads a byte from the buffer.
     *
     * @return the byte
     */
    public byte readByte() {
        return buf[position++];
    }

    /**
     * Read raw data.
     *
     * @param numberOfBytes raw data length.
     * @return raw data
     */
    public byte[] readRawBytes(final int numberOfBytes) {
        final byte[] tmpArr = new byte[numberOfBytes];
        System.arraycopy(buf, position, tmpArr, 0, numberOfBytes);
        position += numberOfBytes;
        return tmpArr;
    }

    public void skipByte() {
        position++;
    }

    public void skipBytes(final int bytesToSkip) {
        position += bytesToSkip;
    }

    /**
     * Skip next length encode binary data.
     */
    public void skipLengthEncodedBytes() {
        int type = this.buf[this.position++] & 0xff;
        switch (type) {
            case 251:
                break;
            case 252:
                position += 2 + (0xffff & (((buf[position] & 0xff) + ((buf[position + 1] & 0xff) << 8))));
                break;
            case 253:
                position += 3 + (0xffffff & ((buf[position] & 0xff)
                        + ((buf[position + 1] & 0xff) << 8)
                        + ((buf[position + 2] & 0xff) << 16)));
                break;
            case 254:
                position += 8 + ((buf[position] & 0xff)
                        + ((long) (buf[position + 1] & 0xff) << 8)
                        + ((long) (buf[position + 2] & 0xff) << 16)
                        + ((long) (buf[position + 3] & 0xff) << 24)
                        + ((long) (buf[position + 4] & 0xff) << 32)
                        + ((long) (buf[position + 5] & 0xff) << 40)
                        + ((long) (buf[position + 6] & 0xff) << 48)
                        + ((long) (buf[position + 7] & 0xff) << 56));
                break;
            default:
                position += type;
        }
    }

    /**
     * Get next binary data length.
     *
     * @return length of next binary data
     */
    public long getLengthEncodedBinary() {
        int type = this.buf[this.position++] & 0xff;
        switch (type) {
            case 251:
                return -1;
            case 252:
                return 0xffff & readShort();
            case 253:
                return 0xffffff & read24bitword();
            case 254:
                return readLong();
            default:
                return type;
        }
    }

    /**
     * Get next data bytes with unknown length.
     *
     * @return the raw binary data
     */
    public byte[] getLengthEncodedBytes() {
        int type = this.buf[this.position++] & 0xff;
        int length;
        switch (type) {
            case 251:
                return null;
            case 252:
                length = 0xffff & readShort();
                break;
            case 253:
                length = 0xffffff & read24bitword();
                break;
            case 254:
                length = (int) ((buf[position++] & 0xff)
                        + ((long) (buf[position++] & 0xff) << 8)
                        + ((long) (buf[position++] & 0xff) << 16)
                        + ((long) (buf[position++] & 0xff) << 24)
                        + ((long) (buf[position++] & 0xff) << 32)
                        + ((long) (buf[position++] & 0xff) << 40)
                        + ((long) (buf[position++] & 0xff) << 48)
                        + ((long) (buf[position++] & 0xff) << 56));
                break;
            default:
                length = type;
        }

        byte[] tmpBuf = new byte[length];
        System.arraycopy(buf, position, tmpBuf, 0, length);
        position += length;
        return tmpBuf;
    }

    /**
     * Get next data bytes with known length.
     *
     * @param length binary data length
     * @return the raw binary data
     */
    public byte[] getLengthEncodedBytesWithLength(long length) {
        if (length < 0) return null;
        final byte[] tmpBuf = new byte[(int) length];
        System.arraycopy(buf, position, tmpBuf, 0, (int) length);
        position += length;
        return tmpBuf;
    }

    public byte getByteAt(final int position) {
        return buf[position];
    }

}
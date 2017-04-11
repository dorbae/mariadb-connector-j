package org.mariadb.jdbc;


import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import java.sql.*;

import static org.junit.Assert.*;


public class BufferTest extends BaseTest {

    static char[] array8m;
    static char[] array20m;
    static char[] array40m;

    static {
        array8m = new char[8000000];
        for (int i = 0; i < array8m.length; i++) {
            array8m[i] = (char) (0x30 + (i % 10));
        }
        array20m = new char[20000000];
        for (int i = 0; i < array20m.length; i++) {
            array20m[i] = (char) (0x30 + (i % 10));
        }
        array40m = new char[40000000];
        for (int i = 0; i < array40m.length; i++) {
            array40m[i] = (char) (0x30 + (i % 10));
        }
    }

    @BeforeClass()
    public static void initClass() throws SQLException {
        createTable("BufferTest", "test longText");
    }

    @Test
    public void send8mTextData() throws SQLException {
        Assume.assumeTrue(checkMaxAllowedPacketMore8m("send8mTextData"));
        sendSqlData(false, array8m);
        sendSqlData(true, array8m);
    }

    @Test
    public void send20mTextData() throws SQLException {
        Assume.assumeTrue(checkMaxAllowedPacketMore20m("send20mTextData"));
        sendSqlData(false, array20m);
        sendSqlData(true, array20m);
    }

    @Test
    public void send40mTextData() throws SQLException {
        Assume.assumeTrue(checkMaxAllowedPacketMore40m("send40mTextData"));
        sendSqlData(false, array40m);
        sendSqlData(true, array40m);
    }

    @Test
    public void send8mByteBufferData() throws SQLException {
        Assume.assumeTrue(checkMaxAllowedPacketMore8m("send8mByteBufferData"));
        sendByteBufferData(false, array8m);
        sendByteBufferData(true, array8m);
    }

    @Test
    public void send20mByteBufferData() throws SQLException {
        Assume.assumeTrue(checkMaxAllowedPacketMore20m("send20mByteBufferData"));
        sendByteBufferData(false, array20m);
        sendByteBufferData(true, array20m);
    }

    @Test
    public void send40mByteBufferData() throws SQLException {
        Assume.assumeTrue(checkMaxAllowedPacketMore40m("send40mByteBufferData"));
        sendByteBufferData(false, array40m);
        sendByteBufferData(true, array40m);
    }


    @Test
    public void send20mSqlNotCompressDataException() throws SQLException {
        try {
            Assume.assumeTrue(!checkMaxAllowedPacketMore20m("send20mSqlNotCompressDataException", false));
            sendSqlData(false, array20m);
            fail("must have thrown exception");
        } catch (SQLException sqlexception) {
            assertTrue("not the expected exception. was " + sqlexception.getMessage(),
                    sqlexception.getMessage().contains("is >= to max_allowed_packet"));
        }
    }

    @Test
    public void send20mSqlCompressDataException() throws SQLException {
        try {
            Assume.assumeTrue(!checkMaxAllowedPacketMore20m("send20mSqlCompressDataException", false));
            sendSqlData(true, array20m);
            fail("must have thrown exception");
        } catch (SQLException sqlexception) {
            assertTrue("not the expected exception. was " + sqlexception.getMessage(),
                    sqlexception.getMessage().contains("is >= to max_allowed_packet"));
        }
    }

    @Test
    public void send40mSqlNotCompressDataException() throws SQLException {
        try {
            Assume.assumeTrue(!checkMaxAllowedPacketMore40m("send40mSqlNotCompressDataException", false));
            sendSqlData(false, array40m);
            fail("must have thrown exception");
        } catch (SQLException sqlexception) {
            assertTrue("not the expected exception. was " + sqlexception.getMessage(),
                    sqlexception.getMessage().contains("is >= to max_allowed_packet"));
        }
    }

    @Test
    public void send40mSqlCompressDataException() throws SQLException {
        try {
            Assume.assumeTrue(!checkMaxAllowedPacketMore40m("send40mSqlCompressDataException", false));
            sendSqlData(true, array40m);
            fail("must have thrown exception");
        } catch (SQLException sqlexception) {
            assertTrue("not the expected exception. was " + sqlexception.getMessage(),
                    sqlexception.getMessage().contains("is >= to max_allowed_packet"));
        }
    }


    @Test
    public void send20mByteBufferNotCompressDataException() throws SQLException {
        try {
            Assume.assumeTrue(!checkMaxAllowedPacketMore20m("send20mByteBufferNotCompressDataException", false));
            sendByteBufferData(false, array20m);
            fail("must have thrown exception");
        } catch (SQLException sqlexception) {
            assertTrue("not the expected exception. was " + sqlexception.getCause().getCause().getMessage(),
                    sqlexception.getCause().getMessage().contains("is >= to max_allowed_packet"));
        }
    }

    @Test
    public void send20mByteBufferCompressDataException() throws SQLException {
        try {
            Assume.assumeTrue(!checkMaxAllowedPacketMore20m("send20mByteBufferCompressDataException", false));
            sendByteBufferData(true, array20m);
            fail("must have thrown exception");
        } catch (SQLException sqlexception) {
            assertTrue("not the expected exception. was " + sqlexception.getCause().getCause().getMessage(),
                    sqlexception.getCause().getMessage().contains("is >= to max_allowed_packet"));
        }
    }

    @Test
    public void send40mByteBufferNotCompressDataException() throws SQLException {
        try {
            Assume.assumeTrue(!checkMaxAllowedPacketMore40m("send40mByteBufferNotCompressDataException", false));
            sendByteBufferData(false, array40m);
            fail("must have thrown exception");
        } catch (SQLException sqlexception) {
            assertTrue("not the expected exception. was " + sqlexception.getCause().getCause().getMessage(),
                    sqlexception.getCause().getMessage().contains("is >= to max_allowed_packet"));
        }
    }

    @Test
    public void send40mByteBufferCompressDataException() throws SQLException {
        try {
            Assume.assumeTrue(!checkMaxAllowedPacketMore40m("send40mByteBufferCompressDataException", false));
            sendByteBufferData(true, array40m);
            fail("must have thrown exception");
        } catch (SQLException sqlexception) {
            assertTrue("not the expected exception. was " + sqlexception.getCause().getCause().getMessage(),
                    sqlexception.getCause().getMessage().contains("is >= to max_allowed_packet"));
        }
    }

    /**
     * Insert data using bytebuffer implementation on PacketOutputStream.
     *
     * @param compression use packet compression
     * @param arr         data to insert
     * @throws SQLException if anything wrong append
     */
    private void sendByteBufferData(boolean compression, char[] arr) throws SQLException {
        try (Connection connection = setConnection("&useCompression=" + compression)) {
            Statement stmt = connection.createStatement();
            stmt.execute("TRUNCATE BufferTest");
            PreparedStatement preparedStatement = connection.prepareStatement("INSERT INTO BufferTest VALUES (?)");
            preparedStatement.setString(1, new String(arr));
            preparedStatement.execute();
            checkResult(arr);
        }
    }

    /**
     * Insert data using sql buffer implementation on PacketOutputStream.
     *
     * @param compression use packet compression
     * @param arr         data to insert
     * @throws SQLException if anything wrong append
     */
    private void sendSqlData(boolean compression, char[] arr) throws SQLException {
        try (Connection connection = setConnection("&useCompression=" + compression)) {
            Statement stmt = connection.createStatement();
            stmt.execute("TRUNCATE BufferTest");
            stmt.execute("INSERT INTO BufferTest VALUES ('" + new String(arr) + "')");
            checkResult(arr);
        }
    }

    private void checkResult(char[] arr) throws SQLException {
        Statement stmt = sharedConnection.createStatement();
        ResultSet rs = stmt.executeQuery("SELECT * FROM BufferTest");
        if (rs.next()) {
            String resString = rs.getString(1);
            char[] cc = resString.toCharArray();
            assertEquals("error in data : length not equal", cc.length, arr.length);
            assertEquals(String.valueOf(cc), resString);

        } else {
            fail("Error, must have result");
        }
    }

}

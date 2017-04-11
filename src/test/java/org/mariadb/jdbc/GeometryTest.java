package org.mariadb.jdbc;

import org.junit.BeforeClass;
import org.junit.Test;

import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import static org.junit.Assert.*;

public class GeometryTest extends BaseTest {
    /**
     * Initialisation.
     *
     * @throws SQLException exception
     */
    @BeforeClass()
    public static void initClass() throws SQLException {
        createTable("geom_test", "g geometry");
    }

    private void geometryTest(String geometryString, String geometryBinary) throws SQLException {
        try (Statement stmt = sharedConnection.createStatement()) {
            stmt.execute("TRUNCATE geom_test");

            String tmpGeometryBinary = geometryBinary;
            if (tmpGeometryBinary == null) {
                try (ResultSet rs = stmt.executeQuery("SELECT AsWKB(GeomFromText('" + geometryString + "'))")) {
                    rs.next();
                    tmpGeometryBinary = printHexBinary(rs.getBytes(1));
                }
            }
            String sql = "INSERT INTO geom_test VALUES (GeomFromText('" + geometryString + "'))";
            stmt.execute(sql);
            try (ResultSet rs = stmt.executeQuery("SELECT AsText(g), AsBinary(g), g FROM geom_test")) {
                rs.next();
                // as text
                assertEquals(geometryString, rs.getString(1));
                // as binary
                String returnWkb = printHexBinary((byte[]) rs.getObject(2));
                assertEquals(tmpGeometryBinary, returnWkb);
                // as object
                Object geometry = null;
                try {
                    geometry = rs.getObject(3);
                } catch (Exception e) {
                    fail();
                }
                String returnGeometry = printHexBinary((byte[]) geometry);
                BigInteger returnNumber = new BigInteger(returnGeometry, 16);
                BigInteger geometryNumber = new BigInteger(tmpGeometryBinary, 16);
                assertEquals(geometryNumber, returnNumber);
            }
        }
    }

    @Test
    public void pointTest() throws SQLException {
        String pointString = "POINT(1 1)";
        String pointWkb = "0101000000000000000000F03F000000000000F03F";
        geometryTest(pointString, pointWkb);
    }

    @Test
    public void lineStringTest() throws SQLException {
        String lineString = "LINESTRING(0 0,1 1,2 2)";
        geometryTest(lineString, null);
    }

    @Test
    public void polygonTest() throws SQLException {
        String polygonString = "POLYGON((0 0,10 0,0 10,0 0))";
        geometryTest(polygonString, null);
    }

    private static final char[] hexCode = "0123456789ABCDEF".toCharArray();

    private String printHexBinary(byte[] data) {
        StringBuilder builder = new StringBuilder(data.length * 2);
        for (byte b : data) {
            builder.append(hexCode[(b >> 4) & 0xF]);
            builder.append(hexCode[(b & 0xF)]);
        }
        return builder.toString();
    }

}

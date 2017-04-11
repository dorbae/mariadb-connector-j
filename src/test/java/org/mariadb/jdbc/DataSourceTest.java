package org.mariadb.jdbc;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.BeforeClass;
import org.junit.Test;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;

import static org.junit.Assert.*;

public class DataSourceTest extends BaseTest {
    protected static final String defConnectToIP = null;
    protected static String connectToIP;

    /**
     * Initialisation.
     */
    @BeforeClass
    public static void beforeClassDataSourceTest() {
        connectToIP = System.getProperty("testConnectToIP", defConnectToIP);
    }

    @Test
    public void testDataSource() throws SQLException {
        MariaDbDataSource ds = new MariaDbDataSource(hostname == null ? "localhost" : hostname, port, database);

        try (Connection connection = ds.getConnection(username, password)) {
            assertEquals(connection.isValid(0), true);
        }
    }

    @Test
    public void testDataSource2() throws SQLException {
        MariaDbDataSource ds = new MariaDbDataSource(hostname == null ? "localhost" : hostname, port, database);
        try (Connection connection = ds.getConnection(username, password)) {
            assertEquals(connection.isValid(0), true);
        }
    }

    @Test
    public void testDataSourceEmpty() throws SQLException {
        MariaDbDataSource ds = new MariaDbDataSource();
        ds.setDatabaseName(database);
        ds.setPort(port);
        ds.setServerName(hostname == null ? "localhost" : hostname);
        try (Connection connection = ds.getConnection(username, password)) {
            assertEquals(connection.isValid(0), true);
        }
    }

    /**
     * Conj-80.
     *
     * @throws SQLException exception
     */
    @Test
    public void setDatabaseNameTest() throws SQLException {
        MariaDbDataSource ds = new MariaDbDataSource(hostname == null ? "localhost" : hostname, port, database);
        try (Connection connection = ds.getConnection(username, password)) {
            connection.createStatement().execute("CREATE DATABASE IF NOT EXISTS test2");
            ds.setDatabaseName("test2");

            try (Connection connection2 = ds.getConnection(username, password)) {
                assertEquals("test2", ds.getDatabaseName());
                assertEquals(ds.getDatabaseName(), connection2.getCatalog());
                connection2.createStatement().execute("DROP DATABASE IF EXISTS test2");
            }
        }
    }

    /**
     * Conj-80.
     *
     * @throws SQLException exception
     */
    @Test
    public void setServerNameTest() throws SQLException {
        Assume.assumeTrue(connectToIP != null);
        MariaDbDataSource ds = new MariaDbDataSource(hostname == null ? "localhost" : hostname, port, database);
        try (Connection connection = ds.getConnection(username, password)) {
            ds.setServerName(connectToIP);
            try (Connection connection2 = ds.getConnection(username, password)) {
                //do nothing
            }
        }
    }

    /**
     * Conj-80.
     *
     * @throws SQLException exception
     */
    @Test // unless port 3307 can be used
    public void setPortTest() throws SQLException {

        MariaDbDataSource ds = new MariaDbDataSource(hostname == null ? "localhost" : hostname, port, database);
        try (Connection connection2 = ds.getConnection(username, password)) {
            //delete blacklist, because can failover on 3306 is filled
            assureBlackList(connection2);
            connection2.close();
        }

        ds.setPort(3407);

        //must throw SQLException
        try {
            ds.getConnection(username, password);
            Assert.fail();
        } catch (SQLException e) {
            //normal error
        }
    }

    /**
     * Conj-123:Session variables lost and exception if set via MariaDbDataSource.setProperties/setURL.
     *
     * @throws SQLException exception
     */
    @Test
    public void setPropertiesTest() throws SQLException {
        MariaDbDataSource ds = new MariaDbDataSource(hostname == null ? "localhost" : hostname, port, database);
        ds.setProperties("sessionVariables=sql_mode='PIPES_AS_CONCAT'");
        try (Connection connection = ds.getConnection(username, password)) {
            ResultSet rs = connection.createStatement().executeQuery("SELECT @@sql_mode");
            if (rs.next()) {
                assertEquals("PIPES_AS_CONCAT", rs.getString(1));
                ds.setUrl(connUri + "&sessionVariables=sql_mode='ALLOW_INVALID_DATES'");
                try (Connection connection2 = ds.getConnection()) {
                    rs = connection2.createStatement().executeQuery("SELECT @@sql_mode");
                    assertTrue(rs.next());
                    assertEquals("ALLOW_INVALID_DATES", rs.getString(1));
                }
            } else {
                fail();
            }
        }

    }

    @Test
    public void setLoginTimeOut() throws SQLException {
        MariaDbDataSource ds = new MariaDbDataSource(hostname == null ? "localhost" : hostname, port, database);
        assertEquals(0, ds.getLoginTimeout());
        ds.setLoginTimeout(10);
        assertEquals(10, ds.getLoginTimeout());
    }

}

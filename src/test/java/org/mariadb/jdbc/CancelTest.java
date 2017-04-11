package org.mariadb.jdbc;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import java.sql.*;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static org.junit.Assert.assertEquals;

public class CancelTest extends BaseTest {


    @Before
    public void cancelSupported() throws SQLException {
        requireMinimumVersion(5, 0);
        Assume.assumeFalse("MAXSCALE".equals(System.getenv("TYPE")));
    }

    @Test
    public void cancelTest() throws SQLException {
        try (Connection tmpConnection = openNewConnection(connUri, new Properties())) {

            Statement stmt = tmpConnection.createStatement();
            ExecutorService exec = Executors.newFixedThreadPool(1);
            //check blacklist shared
            exec.execute(new CancelThread(stmt));
            stmt.execute("select * from information_schema.columns as c1,  information_schema.tables, information_schema.tables as t2");

            //wait for thread endings
            exec.shutdown();
            Assert.fail();
        } catch (SQLException e) {
            //normal exception
        }

    }

    @Test(expected = SQLTimeoutException.class)
    public void timeoutSleep() throws Exception {
        try (Connection tmpConnection = openNewConnection(connUri, new Properties())) {
            Statement stmt = tmpConnection.createStatement();
            stmt.setQueryTimeout(1);
            stmt.execute("select * from information_schema.columns as c1,  information_schema.tables, information_schema.tables as t2");
        }
    }

    @Test
    public void noTimeoutSleep() throws Exception {
        Statement stmt = sharedConnection.createStatement();
        stmt.setQueryTimeout(1);
        stmt.execute("select sleep(0.5)");
    }

    @Test
    public void cancelIdleStatement() throws Exception {
        Statement stmt = sharedConnection.createStatement();
        stmt.cancel();
        ResultSet rs = stmt.executeQuery("select 1");
        rs.next();
        assertEquals(rs.getInt(1), 1);
    }

    private static class CancelThread implements Runnable {
        private final Statement stmt;

        public CancelThread(Statement stmt) {
            this.stmt = stmt;
        }

        @Override
        public void run() {
            try {
                Thread.sleep(100);

                stmt.cancel();

            } catch (SQLException e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }
}

/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package org.xwiki.contrib.authentication.blocking.internal;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

import java.util.HashSet;
import java.util.List;

import javax.inject.Provider;

import org.hamcrest.Matchers;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.slf4j.Logger;
import org.xwiki.contrib.authentication.blocking.BlockedIPInformation;
import org.xwiki.contrib.authentication.blocking.BlockedUserInformation;
import org.xwiki.contrib.authentication.blocking.BlockedUsersService;
import org.xwiki.contrib.authentication.blocking.internal.BlockingAuthConfiguration;
import org.xwiki.contrib.authentication.blocking.internal.DefaultBlockedUserService;
import org.xwiki.model.reference.WikiReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.web.XWikiRequest;

// @ComponentTest
// @TestInstance(Lifecycle.PER_CLASS)
public class DefaultBlockedUserServiceTest
{
    private final String USER_1 = "user1";
    private final String USER_2 = "login2";
    private final String IP_1 = "1.1.1.1";
    private final String IP_2 = "[::FF]";

    // @InjectMockComponents
    BlockedUsersService service;

    @Mock
    Provider<XWikiContext> contextProvider;

    @Mock
    XWikiContext context;

    @Mock
    XWikiRequest request;

    @Mock
    Logger logger;

    @Mock
    BlockingAuthConfiguration configProvider;

    BlockingAuthConfiguration.Config testConfig;

    WikiReference dummyWiki;

    @Before
    public void setUp() throws Exception
    {
        MockitoAnnotations.initMocks(this);

        DefaultBlockedUserService serviceUnderTest = new DefaultBlockedUserService();
        serviceUnderTest.setConfig(configProvider);
        serviceUnderTest.setContextProvider(contextProvider);
        serviceUnderTest.setLogger(logger);
        service = serviceUnderTest;

        testConfig = new BlockingAuthConfiguration.Config();
        testConfig.maxUserAttempts = 2;
        testConfig.blockTimeUser = 100L;
        testConfig.maxIPAttempts = 2;
        testConfig.blockTimeIP = 100L;
        testConfig.whitelistedIPs = new HashSet<String>();

        dummyWiki = new WikiReference("dummy");

        when(request.getRemoteAddr()).thenReturn(IP_1);
        when(context.getRequest()).thenReturn(request);
        when(context.getWikiReference()).thenReturn(dummyWiki);
        // we only test for the main wiki
        when(context.getWikiId()).thenReturn(dummyWiki.getName());
        when(context.isMainWiki()).thenReturn(true);
        when(configProvider.getConfig()).thenReturn(testConfig);
        when(configProvider.getConfig(anyString())).thenReturn(testConfig);
        when(contextProvider.get()).thenReturn(context);
    }

    @Test
    public void testBlockUser()
    {
        service.addFailedLogin(USER_1, context);
        assertFalse(service.isUserBlocked(USER_1));
        assertFalse(service.isUserBlocked(USER_2));
        assertThat(service.getBlockedUsers(), Matchers.empty());
        service.addFailedLogin(USER_1, context);
        assertTrue(service.isUserBlocked(USER_1));
        assertFalse(service.isUserBlocked(USER_2));
        List<BlockedUserInformation> blockedUsers = service.getBlockedUsers();
        assertEquals(1, blockedUsers.size());
        assertEquals(USER_1, blockedUsers.get(0).getUserReference().getName());
    }

    @Test
    public void testUnblockUserAfterBlockTime()
    {
        service.addFailedLogin(USER_1, context);
        service.addFailedLogin(USER_1, context);
        assertTrue(service.isUserBlocked(USER_1));

        waitForExpiry();
        assertFalse(service.isUserBlocked(USER_1));
    }

    @Test
    public void testUnblockUserManually()
    {
        service.addFailedLogin(USER_1, context);
        service.addFailedLogin(USER_1, context);
        assertTrue(service.isUserBlocked(USER_1));

        assertTrue(service.unblockUser(USER_1));

        assertFalse(service.isUserBlocked(USER_1));
    }

    /**
     * this tests a detail about the expiration.
     * currently the login is blocked until the last login failure is older than the expiration
     * no matter how old the other login failures are.
     * this might be changed in another version
     */
    @Test
    public void testUnblockUserOnlyAfterLastAttempt()
    {
        service.addFailedLogin(USER_1, context);
        waitHalfExpiry();
        assertFalse(service.isUserBlocked(USER_1));

        // here one can wait for as long as one wants ...
        /* for (int i=0; i < 100; i++) */ waitForExpiry();
        service.addFailedLogin(USER_1, context);

        // but if the last failed login is inside the expiration window
        // the user is blocked anyway
        waitHalfExpiry();
        assertTrue(service.isUserBlocked(USER_1));

        waitHalfExpiry();
        assertTrue(service.isUserBlocked(USER_1));

        // and it is only unblocked after that entry expires
        waitHalfExpiry();
        assertFalse(service.isUserBlocked(USER_1));
    }

    /**
     * the next two tests test a detail about the expiration.
     * currently existing entries are checked and flushed if expired
     * by the "isBlocked" method as a side effect.
     * (the "isUserBlocked" counts as a check after a successful login,
     * and the "addFailure as a failed login).
     * Both tests only differ in the order of the last two statements.
     * this might be changed in another version
     */
    @Test
    public void testUnblockUserBySuccesfullLogin()
    {
        service.addFailedLogin(USER_1, context);
        assertFalse(service.isUserBlocked(USER_1));
        service.addFailedLogin(USER_1, context);
        assertTrue(service.isUserBlocked(USER_1));

        waitForExpiry();
        assertFalse(service.isUserBlocked(USER_1));
        service.addFailedLogin(USER_1, context);
    }
    @Test
    public void testReBlockUserByUnsuccesfullLogin()
    {
        service.addFailedLogin(USER_1, context);
        assertFalse(service.isUserBlocked(USER_1));
        service.addFailedLogin(USER_1, context);
        assertTrue(service.isUserBlocked(USER_1));

        waitForExpiry();
        service.addFailedLogin(USER_1, context);
        assertTrue(service.isUserBlocked(USER_1));
    }

    @Test
    public void testBlockIp()
    {
        assertThat(service.getBlockedIPs(), Matchers.empty());
        testConfig.maxIPAttempts = 1;
        service.addFailedLogin(USER_1, context);
        assertTrue(service.isIPBlocked(context));
        List<BlockedIPInformation> blockedIPs = service.getBlockedIPs();
        assertEquals(1, blockedIPs.size());
        assertEquals(IP_1, blockedIPs.get(0).getIp());

        when(request.getRemoteAddr()).thenReturn(IP_2);
        assertFalse(service.isIPBlocked(context));
    }

    @Test
    public void testBlockIpIfDisabled()
    {
        testConfig.maxIPAttempts = 0;

        service.addFailedLogin(USER_1, context);
        assertFalse(service.isIPBlocked(context));
        service.addFailedLogin(USER_1, context);
        assertFalse(service.isIPBlocked(context));
    }

    @Test
    public void testUnblockIpManually()
    {
        testConfig.maxIPAttempts = 1;

        service.addFailedLogin(USER_1, context);
        assertTrue(service.isIPBlocked(context));
        assertTrue(service.unblockIP(IP_1));
        assertThat(service.getBlockedIPs(), Matchers.empty());
        assertFalse(service.unblockIP(IP_1));
    }


    @Test
    public void testIpWhitelist()
    {
        testConfig.maxIPAttempts = 1;
        testConfig.maxUserAttempts = 2;
        testConfig.whitelistedIPs.add(IP_2);
        testConfig.whitelistedIPs.add(IP_1);

        service.addFailedLogin(USER_1, context);

        // whitelisted ips should never be blocked
        assertFalse(service.isIPBlocked(context));
        when(request.getRemoteAddr()).thenReturn(IP_2);
        service.addFailedLogin(USER_1, context);
        assertFalse(service.isIPBlocked(context));

        // but users from such IPs should be
        assertTrue(service.isUserBlocked(USER_1));
    }

    //
    // helpers
    //

    private void waitForExpiry()
    {
        try {
            Thread.sleep(101L);
        } catch (InterruptedException e) {
            fail("interrupted while waiting");
        }
    }

    private void waitHalfExpiry()
    {
        try {
            Thread.sleep(45L);
        } catch (InterruptedException e) {
            fail("interrupted while waiting");
        }
    }

}

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

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.authentication.blocking.BlockedIPInformation;
import org.xwiki.contrib.authentication.blocking.BlockedUserInformation;
import org.xwiki.contrib.authentication.blocking.BlockedUsersService;
import org.xwiki.contrib.authentication.blocking.internal.BlockingAuthConfiguration.Config;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.SpaceReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.web.XWikiRequest;

/**
 * Default implementation for the blocked user service.
 *
 * @version $Id$
 * @since 1.0
 * @see {@link BlockedUsersService}
 */
@Component(hints = { "default" }, roles = { BlockedUsersService.class })
@Singleton
public class DefaultBlockedUserService implements BlockedUsersService
{

    private static final String FORWARDED_FOR_IP_HEADER = "X-Forwarded-For";

    private static final String XWIKI_SPACE = "XWiki";

    private static final class LoginData
    {
        private final String username;
        private final String ip;
        private final long timestamp;

        LoginData(String username, String ip)
        {
            this.username = username;
            this.ip = ip;
            this.timestamp = System.currentTimeMillis();
        }
    }

    private final Object lock = new Object();

    private Map<String, List<LoginData>> blockedUsers;
    private Map<String, List<LoginData>> blockedIps;

    @Inject
    private BlockingAuthConfiguration configProvider;

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    @SuppressWarnings("unused")
    private Logger logger;

    /**
     * constructor. initializes the internal data structures
     */
    public DefaultBlockedUserService()
    {
        blockedUsers = new HashMap<>();
        blockedIps = new HashMap<>();
    }

    @Override
    public void addFailedLogin(String username, XWikiContext context)
    {
        LoginData data = new LoginData(username, ip(context));
        synchronized (lock) {
            addToMap(blockedUsers, data.username, data);
            if (!whitelistedIp(data.ip)) {
                addToMap(blockedIps, data.ip, data);
            }
        }
    }

    private static void addToMap(Map<String, List<LoginData>> map, String key, LoginData data)
    {
        if (key == null) {
            return;
        }
        List<LoginData> blockedUserList = map.get(key);
        if (blockedUserList == null) {
            blockedUserList = new ArrayList<>();
            map.put(key, blockedUserList);
        }
        blockedUserList.add(data);
    }

    @Override
    public boolean isUserBlocked(String username)
    {
        Config conf = configProvider.getConfig();
        synchronized (lock) {
            return checkList(blockedUsers.get(username), conf.maxUserAttempts, conf.blockTimeUser);
        }
    }

    @Override
    public boolean isIPBlocked(XWikiContext context)
    {
        Config conf = configProvider.getConfig();
        synchronized (lock) {
            return checkList(blockedIps.get(ip(context)), conf.maxIPAttempts, conf.blockTimeIP);
        }
    }

    @Override
    public List<BlockedUserInformation> getBlockedUsers()
    {
        // TODO: lots of copy & paste in getBlockedIPs
        final List<BlockedUserInformation> blockedUserInfo = new ArrayList<>();
        final XWikiContext context = contextProvider.get();
        final SpaceReference xwikiSpaceRef = new SpaceReference(XWIKI_SPACE, context.getWikiReference());

        synchronized (lock) {
            for (Entry<String, List<LoginData>> entry : blockedUsers.entrySet()) {
                final List<LoginData> loginAttempts = entry.getValue();
                if (loginAttempts.size() < configProvider.getConfig().maxUserAttempts) {
                    continue;
                }
                long lastLoginStamp = 0L;
                for (LoginData loginAttempt : loginAttempts) {
                    lastLoginStamp = Math.max(lastLoginStamp, loginAttempt.timestamp);
                }
                if (lastLoginStamp == 0L) {
                    // this should never happen ...
                    continue;
                }
                BlockedUserInformation userInfo = new BlockedUserInformation();
                DocumentReference userRef = new DocumentReference(entry.getKey(), xwikiSpaceRef);
                userInfo.setUserReference(userRef);
                userInfo.setLastAttempt(new Date(lastLoginStamp));
                blockedUserInfo.add(userInfo);
            }
        }

        // sort by latest attempts first
        Collections.sort(blockedUserInfo, new Comparator<BlockedUserInformation>()
        {
            @Override
            public int compare(BlockedUserInformation info1, BlockedUserInformation info2)
            {
                // we know the dates are never null here, so:
                return info2.getLastAttempt().compareTo(info1.getLastAttempt());
            }
        });

        return blockedUserInfo;
    }

    @Override
    public boolean unblockUser(String userName)
    {
        boolean result;
        synchronized (lock) {
            result = blockedUsers.remove(userName) != null;
        }

        return result;
    }

    @Override
    public List<BlockedIPInformation> getBlockedIPs()
    {
        // TODO: lots of copy & paste from getBlockedUsers
        final List<BlockedIPInformation> blockedIpInfo = new ArrayList<>();

        synchronized (lock) {
            for (Entry<String, List<LoginData>> entry : blockedIps.entrySet()) {
                final List<LoginData> loginAttempts = entry.getValue();
                if (loginAttempts.size() < configProvider.getConfig().maxIPAttempts) {
                    continue;
                }
                long lastLoginStamp = 0L;
                for (LoginData loginAttempt : loginAttempts) {
                    lastLoginStamp = Math.max(lastLoginStamp, loginAttempt.timestamp);
                }
                if (lastLoginStamp == 0L) {
                    // this should never happen ...
                    continue;
                }
                BlockedIPInformation userInfo = new BlockedIPInformation();
                userInfo.setIp(entry.getKey());
                userInfo.setLastAttempt(new Date(lastLoginStamp));
                blockedIpInfo.add(userInfo);
            }
        }

        // sort by latest attempts first
        Collections.sort(blockedIpInfo, new Comparator<BlockedIPInformation>()
        {
            @Override
            public int compare(BlockedIPInformation info1, BlockedIPInformation info2)
            {
                // we know the dates are never null here, so:
                return info2.getLastAttempt().compareTo(info1.getLastAttempt());
            }
        });

        return blockedIpInfo;
    }

    @Override
    public boolean unblockIP(String ip)
    {
        boolean result;
        synchronized (lock) {
            result = blockedIps.remove(ip) != null;
        }

        return result;
    }

    @Override
    public String getCurrentIP()
    {
        XWikiContext context = contextProvider.get();
        if (context == null) {
            return null;
        }
        return ip(context);
    }

    private boolean checkList(List<LoginData> list, int maxAttempts, long blockTime)
    {
        if (maxAttempts <= 0) {
            return false;
        }
        if (list == null || list.isEmpty()) {
            return false;
        }

        long evictTime = System.currentTimeMillis() - blockTime;
        int size = list.size();

        if (list.get(size - 1).timestamp < evictTime) {
            list.clear();
            return false;
        }

        return size >= maxAttempts;
    }

    private String ip(XWikiContext context)
    {
        XWikiRequest request = context.getRequest();

        String ip = request.getRemoteAddr();
        // if we are proxied, then ...
        String proxyIP = request.getHeader(FORWARDED_FOR_IP_HEADER);
        if (!StringUtils.isEmpty(proxyIP) && trustedProxy(ip)) {
            ip = proxyIP.substring(0, proxyIP.indexOf(','));
        }
        return ip;
    }

    private boolean trustedProxy(String ip)
    {
        return configProvider.getConfig().trustedProxies.contains(ip);
    }

    private boolean whitelistedIp(String ip)
    {
        return configProvider.getConfig().whitelistedIPs.contains(ip);
    }

    //
    // the following getter/setter avoid the need for a component mockup
    // for the unit tests
    //

    /**
     * only for tests.
     * 
     * @return the config provider
     */
    BlockingAuthConfiguration getConfig()
    {
        return configProvider;
    }

    /**
     * only for tests.
     * 
     * @param config
     *            the config provider
     */
    void setConfig(BlockingAuthConfiguration config)
    {
        this.configProvider = config;
    }

    /**
     * only for tests.
     * 
     * @param logger
     *            the logger
     */
    void setLogger(Logger logger)
    {
        this.logger = logger;
    }

    /**
     * only for tests.
     * 
     * @param provider
     *            the xwiki context provider
     */
    void setContextProvider(Provider<XWikiContext> provider)
    {
        this.contextProvider = provider;
    }

}

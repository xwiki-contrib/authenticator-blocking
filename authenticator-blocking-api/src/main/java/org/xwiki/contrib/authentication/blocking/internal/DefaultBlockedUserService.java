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
import org.xwiki.model.reference.WikiReference;

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

    private Map<String, Map<String, List<LoginData>>> blockedUsers;
    private Map<String, Map<String, List<LoginData>>> blockedIPs;

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
        blockedIPs = new HashMap<>();
    }

    @Override
    public void addFailedLogin(String username, XWikiContext context)
    {
        LoginData data = new LoginData(username, ip(context));
        synchronized (lock) {
            addToMap(findWikiMapForUser(username, context), data.username, data);
            if (!whitelistedIp(data.ip)) {
                addToMap(findMapByWikiId(blockedIPs, context.getWikiId()), data.ip, data);
            }
        }
    }

    private Map<String, List<LoginData>> findMapByWikiId(Map<String, Map<String, List<LoginData>>> map, String wikiId)
    {
        Map<String, List<LoginData>> mapForWiki = map.get(wikiId);
        if (mapForWiki == null) {
            mapForWiki = new HashMap<>();
            map.put(wikiId, mapForWiki);
        }
        return mapForWiki;
    }

    private String findWikiForUser(String username, XWikiContext context)
    {
        if (context.isMainWiki()) {
            return context.getWikiId();
        }
        DocumentReference userDoc = new DocumentReference(username,
            new SpaceReference(XWIKI_SPACE, new WikiReference(context.getWikiId())));
        if (context.getWiki().exists(userDoc, context)) {
            return context.getWikiId();
        }
        userDoc = userDoc.setWikiReference(new WikiReference(context.getMainXWiki()));
        if (context.getWiki().exists(userDoc, context)) {
            return context.getMainXWiki();
        }
        return context.getWikiId();
    }

    private Map<String, List<LoginData>> findWikiMapForUser(String username, XWikiContext context)
    {
        String wikiId = findWikiForUser(username, context);
        return findMapByWikiId(blockedUsers, wikiId);
    }

    private static void addToMap(Map<String, List<LoginData>> map, String key, LoginData data)
    {
        if (key == null) {
            return;
        }
        List<LoginData> blockedList = map.get(key);
        if (blockedList == null) {
            blockedList = new ArrayList<>();
            map.put(key, blockedList);
        }
        blockedList.add(data);
    }

    @Override
    public boolean isUserBlocked(String username)
    {
        final XWikiContext context = contextProvider.get();
        final String wikiId = findWikiForUser(username, context);
        final Config conf = configProvider.getConfig(wikiId);
        synchronized (lock) {
            return checkList(blockedUsers.get(wikiId), username, conf.maxUserAttempts, conf.blockTimeUser);
        }
    }

    @Override
    public boolean isIPBlocked(XWikiContext context)
    {
        Config conf = configProvider.getConfig();
        synchronized (lock) {
            return checkList(blockedIPs.get(context.getWikiId()), ip(context), conf.maxIPAttempts, conf.blockTimeIP);
        }
    }

    @Override
    public List<BlockedUserInformation> getBlockedUsers()
    {
        // TODO: lots of copy & paste in getBlockedIPs
        final List<BlockedUserInformation> blockedUserInfo = new ArrayList<>();
        final XWikiContext context = contextProvider.get();
        final SpaceReference xwikiSpaceRef = new SpaceReference(XWIKI_SPACE, context.getWikiReference());
        final Config config = configProvider.getConfig();
        if (config.maxUserAttempts <= 0) {
            return blockedUserInfo;
        }

        synchronized (lock) {
            Map<String, List<LoginData>> blockedUsersForWiki = blockedUsers.get(context.getWikiId());
            if (blockedUsersForWiki == null) {
                return blockedUserInfo;
            }

            for (Entry<String, List<LoginData>> entry : blockedUsersForWiki.entrySet()) {
                final List<LoginData> loginAttempts = entry.getValue();
                if (loginAttempts.size() < config.maxUserAttempts) {
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
        XWikiContext context = contextProvider.get();
        synchronized (lock) {
            Map<String, List<LoginData>> blockedUsersForWiki = blockedUsers.get(context.getWikiId());
            if (blockedUsersForWiki == null) {
                result = false;
            } else {
                result = blockedUsersForWiki.remove(userName) != null;
            }
        }

        return result;
    }

    @Override
    public List<BlockedIPInformation> getBlockedIPs()
    {
        // TODO: lots of copy & paste from getBlockedUsers
        final List<BlockedIPInformation> blockedIpInfo = new ArrayList<>();
        Config config = configProvider.getConfig();
        if (config.maxIPAttempts <= 0) {
            return blockedIpInfo;
        }

        synchronized (lock) {
            Map<String, List<LoginData>> blockedIpsForWiki = blockedIPs.get(contextProvider.get().getWikiId());
            if (blockedIpsForWiki == null) {
                return blockedIpInfo;
            }

            for (Entry<String, List<LoginData>> entry : blockedIpsForWiki.entrySet()) {
                final List<LoginData> loginAttempts = entry.getValue();
                if (loginAttempts.size() < config.maxIPAttempts) {
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
        XWikiContext context = contextProvider.get();
        synchronized (lock) {
            Map<String, List<LoginData>> blockedIPsForWiki = blockedIPs.get(context.getWikiId());
            if (blockedIPsForWiki == null) {
                result = false;
            } else {
                result = blockedIPsForWiki.remove(ip) != null;
            }
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

    private boolean checkList(Map<String, List<LoginData>> map, String key, int maxAttempts, long blockTime)
    {
        if (maxAttempts <= 0) {
            return false;
        }
        if (map == null) {
            return false;
        }

        List<LoginData> list = map.get(key);
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

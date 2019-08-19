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

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.WikiReference;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;

/**
 * Provides the blocking auth configuration.
 * 
 * @version $Id$
 * @since 0.1
 */
@Component(hints = { "default" }, roles = { BlockingAuthConfiguration.class })
@Singleton
public class BlockingAuthConfiguration
{
    /** Object to store configuration values. */
    public static final class Config
    {
        /** the maximal number of failed login attempt before the user is blocked. */
        public int maxUserAttempts;

        /** the time the user block is active, in milliseconds. */
        public long blockTimeUser;

        /** the maximal number of failed login attempt before the IP is blocked. */
        public int maxIPAttempts;

        /** the time the IP block is active, in milliseconds. */
        public long blockTimeIP;

        /**
         * a list of whitelisted IPs. If the IP is in the whilelist it will never be blocked.
         */
        public Set<String> whitelistedIPs;

        /**
         * a list of IPs of trusted proxies. If the IP is in the list of trusted proxies,
         * the X-Forward-For header is taken into account to get the real IP.
         */
        public Set<String> trustedProxies;
    }

    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiContext> contextProvider;

    private Map<String, Config> configCache = new HashMap<>();

    /**
     * load a configuration from the database.
     *
     * @param context
     *            the current context
     * @return the config as loaded from the database
     * @throws XWikiException
     *             if the config could not be loaded
     */
    protected Config loadConfig(XWikiContext context) throws XWikiException
    {
        Config conf = new Config();

        XWikiDocument doc = context.getWiki().getDocument(AuthConfigInitializer.CONFIG_REF, context);
        BaseObject configObj = doc.getXObject(AuthConfigInitializer.CLASS_REF);

        if (configObj != null) {
            conf.maxUserAttempts = configObj.getIntValue(AuthConfigInitializer.MAX_USER_ATTEMPTS);
            conf.blockTimeUser = configObj.getLongValue(AuthConfigInitializer.USER_BLOCK_TIME) * 1000L;
            conf.maxIPAttempts = configObj.getIntValue(AuthConfigInitializer.MAX_IP_ATTEMPTS);
            conf.blockTimeIP = configObj.getLongValue(AuthConfigInitializer.IP_BLOCK_TIME) * 1000L;
            conf.whitelistedIPs = asSet(configObj.getListValue(AuthConfigInitializer.TRUSTED_PROXIES));
            conf.trustedProxies = asSet(configObj.getListValue(AuthConfigInitializer.TRUSTED_PROXIES));
        } else {
            throw new XWikiException("could not load mandatory config object from " + doc,
                new NullPointerException(AuthConfigInitializer.CLASS_REF.toString()));
        }

        return conf;
    }

    /**
     * get the auth config for the current wiki.
     *
     * @return a configuration, never null
     */
    public Config getConfig()
    {
        Config conf;
        XWikiContext context = contextProvider.get();
        final String wiki = context.getWikiId();
        synchronized (configCache) {
            conf = configCache.get(wiki);
        }
        if (conf == null) {
            try {
                conf = loadConfig(context);
                synchronized (configCache) {
                    configCache.put(wiki, conf);
                }
            } catch (XWikiException e) {
                logger.error("could not load config", e);
                conf = new Config();
            }

        }
        return conf;
    }

    /**
     * Flush the config cache. The next class to {@link #getConfig()} will load the new values.
     * 
     * @param wiki
     *            the affected wiki
     */
    public void flushCacheForWiki(WikiReference wiki)
    {
        synchronized (configCache) {
            if (wiki == null) {
                configCache.clear();
                logger.info("cleared config cache!");
            } else {
                configCache.remove(wiki.getName());
                logger.info("cleared config cache for wiki [{}]", wiki.getName());
            }
        }
    }


    private Set<String> asSet(@SuppressWarnings("rawtypes") List listValue)
    {
        Set<String> values = new HashSet<String>();
        for (Object item : listValue) {
            if (item != null) {
                values.add(item.toString().trim());
            }
        }
        return values;
    }
}

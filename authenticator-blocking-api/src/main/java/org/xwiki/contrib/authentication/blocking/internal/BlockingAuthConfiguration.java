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
import javax.inject.Named;
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
 * @since 1.0
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

    @Inject
    @Named(AuthConfigInitializer.CLASSNAME)
    private AuthConfigInitializer configInit;

    private Map<String, Config> configCache = new HashMap<>();

    /**
     * load a configuration from the database.
     *
     * @param context
     *            the current context
     * @return the config as loaded from the current wiki; null if not found
     * @throws XWikiException
     *             if the config could not be loaded
     */
    protected Config loadConfig(XWikiContext context) throws XWikiException
    {
        XWikiDocument doc = context.getWiki().getDocument(AuthConfigInitializer.CONFIG_REF, context);
        BaseObject configObj = doc.getXObject(AuthConfigInitializer.CLASS_REF);

        if (configObj == null) {
            return null;
        }
        Config conf = new Config();
        conf.maxUserAttempts = configObj.getIntValue(AuthConfigInitializer.MAX_USER_ATTEMPTS);
        conf.blockTimeUser = configObj.getLongValue(AuthConfigInitializer.USER_BLOCK_TIME) * 1000L;
        conf.maxIPAttempts = configObj.getIntValue(AuthConfigInitializer.MAX_IP_ATTEMPTS);
        conf.blockTimeIP = configObj.getLongValue(AuthConfigInitializer.IP_BLOCK_TIME) * 1000L;
        conf.whitelistedIPs = asSet(configObj.getListValue(AuthConfigInitializer.TRUSTED_PROXIES));
        conf.trustedProxies = asSet(configObj.getListValue(AuthConfigInitializer.TRUSTED_PROXIES));
        logger.debug("loaded blocking auth config from wiki [{}]", context.getWikiId());
        return conf;
    }

    /**
     * get the auth config for the current wiki.
     *
     * @return a configuration, never null, but instead an empty dummy if no values found
     */
    public Config getConfig()
    {
        return getConfig(contextProvider.get().getWikiId());
    }

    /**
     * get the auth config for the given wiki.
     *
     * @param wikiId the id of the wiki, should not be null
     * @return a configuration, never null, but instead an empty dummy if no values found
     * @since 1.1
     */
    public Config getConfig(String wikiId)
    {
        Config conf;
        synchronized (configCache) {
            conf = configCache.get(wikiId);
        }
        if (conf == null) {
            final XWikiContext context = contextProvider.get();

            String originalWikiId = context.getWikiId();
            try {
                try {
                    context.setWikiId(wikiId);
                    conf = loadConfig(context);
                    if (conf == null && !context.isMainWiki()) {
                        context.setWikiId(context.getMainXWiki());
                        conf = loadConfig(context);
                    }
                    if (conf == null) {
                        conf = new Config();
                    }
                    synchronized (configCache) {
                        configCache.put(wikiId, conf);
                    }
                    logger.debug("cached blocking auth config for wiki [{}]", wikiId);
                } catch (XWikiException e) {
                    logger.error("could not load config", e);
                    conf = new Config();
                }
            } finally {
                context.setWikiId(originalWikiId);
            }
        }
        return conf;
    }


    /**
     * Flush the config cache. The next class to {@link #getConfig()} will load the new values.
     * 
     * @param wiki
     *            the affected wiki; if null then flush cache for all wikis
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

    /**
     * check of the current wiki has its own configuration object.
     * @return true if the wiki has a config object
     * @since 1.1
     */
    public boolean hasOwnConfig()
    {
        try {
            final XWikiContext context = contextProvider.get();
            final XWikiDocument doc = context.getWiki().getDocument(AuthConfigInitializer.CONFIG_REF,
                context);
            return doc.getXObject(AuthConfigInitializer.CLASS_REF) != null;
        } catch (XWikiException e) {
            logger.debug("could not check if config exists", e);
            return false;
        }
    }

    /**
     * create a new configuration, if not already present.
     * @return true if a new config was created
     * @since 1.1
     */
    public boolean createConfig()
    {
        XWikiContext context = contextProvider.get();

        synchronized (configCache) {
            try {
                Config cfg = loadConfig(context);
                if (cfg != null) {
                    return false;
                }
            } catch (XWikiException e) {
                logger.info("could not find config for wiki [{}]); will create a new one",
                    context.getWikiId(), e);
            }
        }

        return configInit.createNewConfigObject(context);
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

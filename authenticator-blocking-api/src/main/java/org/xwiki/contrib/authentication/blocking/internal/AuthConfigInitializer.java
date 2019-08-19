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

import java.util.Arrays;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.context.Execution;
import org.xwiki.model.EntityType;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.LocalDocumentReference;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.AbstractMandatoryClassInitializer;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.user.api.XWikiRightService;

/**
 * Initializes the config objects.
 * 
 * @version $Id$
 * @since 0.1
 */
@Component
@Named(AuthConfigInitializer.CLASSNAME)
@Singleton
public class AuthConfigInitializer extends AbstractMandatoryClassInitializer
{
    private static final char DOT = '.';

    private static final String LOCAL_SPACENAME = "BlockingAuth";
    private static final String LOCAL_CLASSNAME = "ConfigClass";
    private static final String LOCAL_INSTANCENAME = "Config";

    static final String CLASSNAME = XWiki.SYSTEM_SPACE + DOT + LOCAL_SPACENAME + DOT + LOCAL_CLASSNAME;

    static final LocalDocumentReference CLASS_REF;
    static final LocalDocumentReference CONFIG_REF;

    static final LocalDocumentReference SUPERADMIN_REF;

    // class field names

    static final String MAX_USER_ATTEMPTS = "maxUserAttempts";
    static final String USER_BLOCK_TIME = "userBlockTime";
    static final String MAX_IP_ATTEMPTS = "maxIPAttempts";
    static final String IP_BLOCK_TIME = "ipBlockTime";
    static final String WHILELISTED_IPS = "ipWhitelist";
    static final String TRUSTED_PROXIES = "trustedProxies";

    @Inject
    private Logger logger;

    @Inject
    // Provider<XWikiContext> instead?
    private Execution contextProvider;

    static {
        EntityReference xwikiSpace = new EntityReference(XWiki.SYSTEM_SPACE, EntityType.SPACE, null);
        EntityReference spaceRef = new EntityReference(LOCAL_SPACENAME, EntityType.SPACE, xwikiSpace);

        CLASS_REF = new LocalDocumentReference(LOCAL_CLASSNAME, spaceRef);

        CONFIG_REF = new LocalDocumentReference(LOCAL_INSTANCENAME, spaceRef);
        SUPERADMIN_REF = new LocalDocumentReference(XWikiRightService.SUPERADMIN_USER, spaceRef);
    }

    /**
     * constructor.
     */
    public AuthConfigInitializer()
    {
        super(CLASS_REF);
    }

    @Override
    protected void createClass(BaseClass xclass)
    {
        final String integerType = "integer";
        final String longType = "long";
        final String inputField = "input";
        final String sep = ", ";

        xclass.addNumberField(MAX_USER_ATTEMPTS, "Maximal attempts before a user is blocked", 10, integerType);
        xclass.addNumberField(USER_BLOCK_TIME, "Timeout when maximum of failed logins reached", 30, longType);

        xclass.addNumberField(MAX_IP_ATTEMPTS, "Maximal attempts before an IP is blocked", 10, integerType);
        xclass.addNumberField(IP_BLOCK_TIME, "Timeout when maximum of failed attempts per IP reached", 30, longType);

        xclass.addStaticListField(WHILELISTED_IPS, "Whitelisted IPs", 5, true, false, "", inputField, sep);
        xclass.addStaticListField(TRUSTED_PROXIES, "List of trusted proxies", 5, true, false, "", inputField, sep);
    }

    /**
     * Update the class and create a config object with default values, if missing.
     * 
     * @param document
     *            the document containing the class
     */
    @Override
    public boolean updateDocument(XWikiDocument document)
    {
        boolean modified = super.updateDocument(document);

        Object context = contextProvider.getContext().getProperty(XWikiContext.EXECUTIONCONTEXT_KEY);
        if (context != null && (context instanceof XWikiContext)) {
            XWikiContext xcontext = (XWikiContext) context;
            XWiki currentWiki = xcontext.getWiki();
            try {
                XWikiDocument doc = currentWiki.getDocument(CONFIG_REF, xcontext);
                boolean needSave = doc.isNew();
                BaseObject defaults = doc.getXObject(CLASS_REF);
                if (defaults == null) {
                    logger.debug("create default configuration for wiki [{}]", currentWiki.getName());

                    doc.createXObject(CLASS_REF, xcontext);
                    needSave = true;
                    defaults = doc.getXObject(CLASS_REF);

                    defaults.setIntValue(MAX_USER_ATTEMPTS, 3);
                    defaults.setLongValue(USER_BLOCK_TIME, 15 * 60L);

                    defaults.setIntValue(MAX_IP_ATTEMPTS, 0);
                    defaults.setLongValue(IP_BLOCK_TIME, 0L);

                    defaults.setStringListValue(WHILELISTED_IPS, Arrays.<String>asList());
                    defaults.setStringListValue(TRUSTED_PROXIES, Arrays.asList("127.0.0.1", "[::1]"));
                }

                if (needSave) {
                    doc.setAuthorReference(new DocumentReference(SUPERADMIN_REF, xcontext.getWikiReference()));
                    currentWiki.saveDocument(doc, xcontext);
                }
            } catch (XWikiException e) {
                logger.warn("could not initialize default config", e);
            }
        }

        return modified;
    }

}

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

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.bridge.event.AbstractDocumentEvent;
import org.xwiki.bridge.event.DocumentCreatedEvent;
import org.xwiki.bridge.event.DocumentUpdatedEvent;
import org.xwiki.component.annotation.Component;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.doc.XWikiDocument;

/**
 * Flushes config in case the config data gets edited.
 * 
 * @version $Id$
 * @since 0.1
 */
@Component
@Named("org.xwiki.contrib.authentication.blocking.internal.AuthConfigEditListener")
@Priority(1100)
@Singleton
public class AuthConfigEditListener extends AbstractEventListener
{
    @Inject
    private BlockingAuthConfiguration config;

    /**
     * Constructor. Defines which events we listen to.
     */
    public AuthConfigEditListener()
    {
        super(AuthConfigEditListener.class.getName(),
            Arrays.asList(new DocumentUpdatedEvent(), new DocumentCreatedEvent()));
    }

    /**
     * flushes cache if config document is saved.
     */
    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        if (event instanceof AbstractDocumentEvent) {
            XWikiDocument currentDocument = (XWikiDocument) source;
            XWikiContext context = (XWikiContext) data;

            DocumentReference currentDocRef = currentDocument.getDocumentReference();
            WikiReference currentWiki = context.getWikiReference();
            DocumentReference configRef = new DocumentReference(AuthConfigInitializer.CONFIG_REF, currentWiki);

            if (configRef.equals(currentDocRef)) {
                config.flushCacheForWiki(currentWiki);
            }
        }
    }
}

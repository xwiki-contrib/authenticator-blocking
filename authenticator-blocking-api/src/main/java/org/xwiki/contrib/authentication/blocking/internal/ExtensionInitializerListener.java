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

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.phase.Initializable;
import org.xwiki.component.phase.InitializationException;
import org.xwiki.observation.AbstractEventListener;
import org.xwiki.observation.event.Event;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.user.api.XWikiAuthService;

/**
 * Listener used to update the auth class in the {@link XWiki} instance after an upgrade/uninstall.
 * 
 * @version $Id$
 */
@Component
@Singleton
@Named(ExtensionInitializerListener.NAME)
public class ExtensionInitializerListener extends AbstractEventListener implements Initializable
{
    /**
     * The name of the listener.
     */
    public static final String NAME = "org.xwiki.contrib.authentication.blocking.internal.ExtensionInitializerListener";

    @Inject
    private Provider<XWikiContext> contextProvider;

    @Inject
    private Logger logger;

    /**
     * @param name
     * @param events
     */
    public ExtensionInitializerListener()
    {
        super(NAME);
    }

    @Override
    public void initialize() throws InitializationException
    {
        XWikiContext xcontext = this.contextProvider.get();

        // When the extension is reloaded after an upgrade (or uninstall of another extension)
        // we must make sure the registered BlockingAuthServiceImpl is based on the new version
        if (xcontext != null && xcontext.getWiki() != null) {
            XWikiAuthService authService = xcontext.getWiki().getAuthService();

            // The new version is in a new classloader so the class is not the same from Java point of view but it has
            // the same class name
            if (!(authService instanceof BlockingAuthServiceImpl)
                && authService.getClass().getName().equals(BlockingAuthServiceImpl.class.getName())) {
                // Replace the current auth service if it's the old LDAP one
                xcontext.getWiki().setAuthService(new BlockingAuthServiceImpl());
            }
        }
    }

    @Override
    public void onEvent(Event event, Object source, Object data)
    {
        // Don't really listening to any event
    }
}

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
package org.xwiki.contrib.authentication.blocking.script;

import java.util.List;
import java.util.function.Supplier;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.context.Execution;
import org.xwiki.contrib.authentication.blocking.BlockedIPInformation;
import org.xwiki.contrib.authentication.blocking.BlockedUserInformation;
import org.xwiki.contrib.authentication.blocking.BlockedUsersService;
import org.xwiki.contrib.authentication.blocking.internal.BlockingAuthConfiguration;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.xpn.xwiki.XWikiContext;

/**
 * Script service to expose data to script and templating languages about blocked users and IPs.
 * 
 * @version $Id$
 * @since 0.1
 */
@Component
@Named("blockingauth")
@Singleton
public class BlockingAuthScriptService implements ScriptService
{
    /**
     * The key under which the last encountered error is stored in the current execution context.
     */
    private static final String ERROR_KEY = "scriptservice.blockingauth.error";

    @Inject
    private Execution execution;

    @Inject
    private Provider<XWikiContext> wikiContextProvider;

    @Inject
    private BlockedUsersService blockedUsers;

    @Inject
    private BlockingAuthConfiguration blockedConfig;

    @Inject
    private Provider<ContextualAuthorizationManager> authManagerProvider;

    /**
     * @return the XWiki context associated with this execution.
     */
    private XWikiContext getXWikiContext()
    {
        return (XWikiContext) this.execution.getContext().getProperty(XWikiContext.EXECUTIONCONTEXT_KEY);
    }

    /**
     * @return @code true if the currently configured authentication class is the blocking one.
     * @since 0.1
     */
    public boolean isBlockingAuthenticator()
    {
        return org.xwiki.contrib.authentication.blocking.internal.BlockingAuthServiceImpl.class
            .isAssignableFrom(getXWikiContext().getWiki().getAuthService().getClass());
    }

    /**
     * get the list of blocked users.
     *
     * @return a list, or null if an error happened
     */
    public List<BlockedUserInformation> getBlockedUsers()
    {
        return doWithExceptionHandling(() -> {
            return blockedUsers.getBlockedUsers();
        });
    }

    /**
     * unblock a given user.
     *
     * @param userLogin
     *     the login for a blocked user
     * @return the result of the operation, or null in case of errors
     */
    public Boolean unblockUser(final String userLogin)
    {
        return doWithExceptionHandling(() -> {
            return blockedUsers.unblockUser(userLogin);
        });
    }

    /**
     * get the list of blocked IPs.
     *
     * @return a list, or null if an error happened
     */
    public List<BlockedIPInformation> getBlockedIPs()
    {
        return doWithExceptionHandling(() -> {
            return blockedUsers.getBlockedIPs();
        });
    }

    /**
     * unblock a given ip.
     *
     * @param ip
     *     the blocked ip
     * @return the result of the operation, or null in case of errors
     */
    public Boolean unblockIP(final String ip)
    {
        return doWithExceptionHandling(() -> {
            return blockedUsers.unblockIP(ip);
        });
    }

    /**
     * return the IP used to make the current request.
     * this is an informational method to inform the admin which IP is currently used,
     * for example to add it to the whitelist of IPs which are never blocked.
     *
     * if the IP cannot be determined, e.g. if there is no current request, return null
     *
     * @return the current IP as a string, or null in case of errors
     */
    public String getCurrentIP()
    {
        return doWithExceptionHandling(() -> {
            return blockedUsers.getCurrentIP();
        });
    }

    /**
     * fetch the result from the given provider after checking for admin rights.
     *
     * @param <R>
     *            the type of the returned value
     * @param whatToDo
     * @return the result from the provider, or null if an error happened
     * @see {{@link #getError()}
     */
    private <R> R doWithExceptionHandling(Supplier<R> whatToDo)
    {
        try {
            authManagerProvider.get().checkAccess(Right.ADMIN, wikiContextProvider.get().getWikiReference());
            return whatToDo.get();
        } catch (Exception e) {
            setError(e);
        }
        return null;
    }

    /**
     * check if we actually have a local config available or inherit it from the main wiki.
     *
     * @return true if there is a non-empty config in the cache
     * @since 1.1
     */
    public boolean hasLocalConfig() {
        return blockedConfig.hasOwnConfig();
    }

    /**
     * create a config object for the current wiki.
     *
     * if newly created, the configuration will be filled with hard wired default values.
     * @return true if the configuration was created successfully.
     * @since 1.1
     */
    public boolean createLocalConfig()
    {
        return doWithExceptionHandling(() -> {
            return blockedConfig.createConfig();
        });
    }

    /**
     * Get the error generated while performing the previously called action.
     *
     * @return an eventual exception or {@code null} if no exception was thrown
     * @since 0.1
     */
    public Exception getError()
    {
        return (Exception) this.execution.getContext().getProperty(ERROR_KEY);
    }

    /**
     * Store a caught exception in the context, so that it can be later retrieved using {@link #getError()}.
     *
     * @param e
     *            the exception to store, can be {@code null} to clear the previously stored exception
     * @see #getError()
     * @since 0.1
     */
    private void setError(Exception e)
    {
        this.execution.getContext().setProperty(ERROR_KEY, e);
    }

}

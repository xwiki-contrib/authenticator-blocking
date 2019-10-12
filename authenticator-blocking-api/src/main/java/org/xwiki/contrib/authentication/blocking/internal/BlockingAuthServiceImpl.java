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

import java.security.Principal;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xwiki.contrib.authentication.blocking.BlockedUsersService;

import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.user.api.XWikiAuthService;
import com.xpn.xwiki.user.impl.xwiki.XWikiAuthServiceImpl;
import com.xpn.xwiki.web.Utils;

/**
 * A authentication service that also counts failed logins.
 * After a configurable number of failures block further login attempts
 * until no failures have happened for a certain time.
 * 
 * @version $Id$
 * @since 1.0
 */
public class BlockingAuthServiceImpl extends XWikiAuthServiceImpl implements XWikiAuthService
{

    private static final String ERROR_MESSAGE_KEY = "message";

    private static final Logger LOGGER = LoggerFactory.getLogger(BlockingAuthServiceImpl.class);

    @SuppressWarnings("deprecation")
    private BlockedUsersService getService()
    {
        return Utils.getComponent(BlockedUsersService.class);
    }

    @Override
    public Principal authenticate(String username, String password, XWikiContext context) throws XWikiException
    {

        if (!StringUtils.isEmpty(username)) {
            if (LOGGER.isTraceEnabled()) {
                LOGGER.trace("Starting authentication");
            }

            if (getService().isUserBlocked(username)) {
                LOGGER.info("skip login for [{}]; is blocked", username);
                getService().addFailedLogin(username, context);
                context.put(ERROR_MESSAGE_KEY, "contrib.blockingauth.user.blocked");
                return null;
            }

            if (getService().isIPBlocked(context)) {
                LOGGER.info("skip login for [{}]; IP [{}] is blocked", username, getService().getCurrentIP());
                getService().addFailedLogin(username, context);
                context.put(ERROR_MESSAGE_KEY, "contrib.blockingauth.ip.blocked");
                return null;
            }
        }

        Principal principal = super.authenticate(username, password, context);

        if (!StringUtils.isEmpty(username)) {
            if (principal == null) {
                LOGGER.debug("add login failure for user [{}] and IP [{}]", username, getService().getCurrentIP());
                getService().addFailedLogin(username, context);
            }
        }

        return principal;
    }

}

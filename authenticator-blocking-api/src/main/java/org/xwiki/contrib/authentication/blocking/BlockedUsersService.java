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
package org.xwiki.contrib.authentication.blocking;

import java.util.List;

import com.xpn.xwiki.XWikiContext;

/**
 * Keeps information about blocked users and IPs.
 * 
 * @version $Id$
 * @since 0.1
 */
public interface BlockedUsersService
{

    /**
     * add record about a login that failed.
     * 
     * @param username
     *            the user name for which the login failed
     * @param context
     *            the wiki context,  used to determine the IP
     */
    void addFailedLogin(String username, XWikiContext context);

    /**
     * check if user is blocked.
     * This should be called on every attempted login.
     * Note that this method is not side effect free, but also cleans up expired
     * login failures if the last failure is expired.
     * 
     * @param username
     *            the user name to check
     * @return true if the user is blocked
     */
    boolean isUserBlocked(String username);

    /**
     * check if IP is blocked.
     * 
     * @param context
     *            the context from which the IP will be determined
     * @return true if the IP is blocked
     */
    boolean isIPBlocked(XWikiContext context);

    /**
     * get the list of all currently blocked users.
     * you can modify this list, but this has no effect on the state of blocked users.
     * @return list of {@link BlockedUserInformation}, maybe empty, but never null
     */
    List<BlockedUserInformation> getBlockedUsers();

    /**
     * get the list of all currently blocked IPs.
     * you can modify this list, but this has no effect on the state of blocked IPs.
     * @return list of {@link BlockedIPInformation}, maybe empty, but never null
     */
    List<BlockedIPInformation> getBlockedIPs();

    /**
     * unblock a given user.
     * @param login the login of a user
     * @return true if the user has been unblocked.
     */
    boolean unblockUser(String login);

    /**
     * unblock a given IP.
     * @param ip the ip to unblock as a string
     * @return true if the ip has been unblocked.
     */
    boolean unblockIP(String ip);

    /**
     * return the IP used to make the current request.
     * if the IP cannot be determined, e.g. if there is no current request, return null
     *
     * @return the result of the operation, or null in case of errors
     */
    String getCurrentIP();

}

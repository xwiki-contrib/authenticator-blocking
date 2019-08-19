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

import java.util.Date;

import org.apache.commons.lang3.builder.ToStringBuilder;

/**
 * helper class to store information about a blocked IP.
 *
 * @version $Id: $
 * @since 0.1
 */
public class BlockedIPInformation
{

    private String ip;

    private Date lastAttempt;

    /**
     * the blocked ip.
     *
     * @return the id, never null
     */
    public String getIp()
    {
        return ip;
    }

    /**
     * set the blocked ip.
     *
     * @param ip
     *            the ip as string, should not be null
     */
    public void setIp(String ip)
    {
        this.ip = ip;
    }

    /**
     * the last failed login attempt.
     *
     * @return date of the last login, never null
     */
    public Date getLastAttempt()
    {
        return lastAttempt;
    }

    /**
     * set the date of the last failed login.
     *
     * @param lastAttempt
     *            date of last login attempt, should not be null
     */
    public void setLastAttempt(Date lastAttempt)
    {
        this.lastAttempt = lastAttempt;
    }

    /**
     * a simple string representation.
     *
     * @return this object as string.
     */
    @Override
    public String toString()
    {
        return ToStringBuilder.reflectionToString(this);
    }

}

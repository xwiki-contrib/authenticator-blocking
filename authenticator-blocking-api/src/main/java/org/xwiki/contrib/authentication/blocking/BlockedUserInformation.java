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
import org.xwiki.model.reference.DocumentReference;

/**
 * helper class to store information about a blocked user account.
 *
 * @version $Id: $
 * @since 0.1
 */
public class BlockedUserInformation
{

    private DocumentReference userReference;

    private Date lastAttempt;

    /**
     * the document reference to the blocked user profile.
     *
     * @return a documentReference, never null
     */
    public DocumentReference getUserReference()
    {
        return userReference;
    }

    /**
     * set the reference to the blocked users profile.
     *
     * @param userReference
     *            should be a reference to a user profile
     */
    public void setUserReference(DocumentReference userReference)
    {
        this.userReference = userReference;
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

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.syncope.common.lib.to;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.ArrayList;
import java.util.List;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElementWrapper;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.apache.syncope.common.lib.AbstractBaseBean;
import org.apache.syncope.common.lib.types.IntMappingType;
import org.apache.syncope.common.lib.types.TraceLevel;

@XmlRootElement(name = "notification")
@XmlType
public class NotificationTO extends AbstractBaseBean {

    private static final long serialVersionUID = -6145117115632592612L;

    private Long key;

    private List<String> events = new ArrayList<>();

    private String userAbout;

    private String roleAbout;

    private String recipients;

    private List<String> staticRecipients = new ArrayList<>();

    private IntMappingType recipientAttrType;

    private String recipientAttrName;

    private boolean selfAsRecipient;

    private String sender;

    private String subject;

    private String template;

    private TraceLevel traceLevel;

    private boolean active;

    public String getUserAbout() {
        return userAbout;
    }

    public void setUserAbout(final String userAbout) {
        this.userAbout = userAbout;
    }

    public String getRoleAbout() {
        return roleAbout;
    }

    public void setRoleAbout(final String roleAbout) {
        this.roleAbout = roleAbout;
    }

    @XmlElementWrapper(name = "events")
    @XmlElement(name = "event")
    @JsonProperty("events")
    public List<String> getEvents() {
        return events;
    }

    @XmlElementWrapper(name = "staticRecipients")
    @XmlElement(name = "staticRecipient")
    @JsonProperty("staticRecipients")
    public List<String> getStaticRecipients() {
        return staticRecipients;
    }

    public Long getKey() {
        return key;
    }

    public void setKey(Long key) {
        this.key = key;
    }

    public String getRecipients() {
        return recipients;
    }

    public void setRecipients(final String recipients) {
        this.recipients = recipients;
    }

    public String getRecipientAttrName() {
        return recipientAttrName;
    }

    public void setRecipientAttrName(final String recipientAttrName) {
        this.recipientAttrName = recipientAttrName;
    }

    public IntMappingType getRecipientAttrType() {
        return recipientAttrType;
    }

    public void setRecipientAttrType(final IntMappingType recipientAttrType) {
        this.recipientAttrType = recipientAttrType;
    }

    public boolean isSelfAsRecipient() {
        return selfAsRecipient;
    }

    public void setSelfAsRecipient(final boolean selfAsRecipient) {
        this.selfAsRecipient = selfAsRecipient;
    }

    public String getSender() {
        return sender;
    }

    public void setSender(final String sender) {
        this.sender = sender;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(final String subject) {
        this.subject = subject;
    }

    public String getTemplate() {
        return template;
    }

    public void setTemplate(final String template) {
        this.template = template;
    }

    public TraceLevel getTraceLevel() {
        return traceLevel;
    }

    public void setTraceLevel(final TraceLevel traceLevel) {
        this.traceLevel = traceLevel;
    }

    public boolean isActive() {
        return active;
    }

    public void setActive(final boolean active) {
        this.active = active;
    }
}

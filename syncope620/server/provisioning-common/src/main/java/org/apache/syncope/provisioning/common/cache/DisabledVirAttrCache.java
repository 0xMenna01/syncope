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
package org.apache.syncope.provisioning.common.cache;

import org.apache.syncope.common.lib.types.AttributableType;
import org.apache.syncope.provisioning.api.cache.VirAttrCache;
import org.apache.syncope.provisioning.api.cache.VirAttrCacheValue;

/**
 * Empty virtual attribute value cache implementation.
 */
public class DisabledVirAttrCache implements VirAttrCache {

    @Override
    public void expire(final AttributableType type, final Long id, final String schemaName) {
        // nothing to do
    }

    @Override
    public VirAttrCacheValue get(final AttributableType type, final Long id, final String schemaName) {
        return null;
    }

    @Override
    public boolean isValidEntry(VirAttrCacheValue value) {
        return false;
    }

    @Override
    public void put(
            final AttributableType type, final Long id, final String schemaName, final VirAttrCacheValue value) {

        // nothing to do
    }

}

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
package org.apache.syncope.core.rest.cxf;

import java.net.URL;
import javax.ws.rs.container.ContainerRequestContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Automatically loads available javadocs from class loader (when {@link java.net.URLClassLoader}).
 */
public class WadlGenerator extends org.apache.cxf.jaxrs.model.wadl.WadlGenerator {

    private static final Logger LOG = LoggerFactory.getLogger(WadlGenerator.class);

    private boolean inited = false;

    @Override
    public void filter(final ContainerRequestContext context) {
        synchronized (this) {
            if (!inited) {
                URL[] javaDocURLs = JavaDocUtils.getJavaDocURLs();
                try {
                    super.setJavaDocPath(javaDocURLs[0].toExternalForm());
                } catch (Exception e) {
                    LOG.error("Could not load Javadocs from {}", javaDocURLs[0], e);
                }

                inited = true;
            }
        }

        super.filter(context);
    }

}

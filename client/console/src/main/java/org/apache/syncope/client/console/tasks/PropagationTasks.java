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
package org.apache.syncope.client.console.tasks;

import static org.apache.syncope.client.console.panels.MultilevelPanel.FIRST_LEVEL_ID;

import org.apache.syncope.client.console.panels.MultilevelPanel;
import org.apache.syncope.client.console.wicket.markup.html.bootstrap.dialog.BaseModal;
import org.apache.syncope.common.lib.to.AnyTO;
import org.apache.syncope.common.lib.to.PropagationTaskTO;
import org.apache.wicket.PageReference;
import org.apache.wicket.ajax.AjaxRequestTarget;

public class PropagationTasks extends AbstractTasks {

    private static final long serialVersionUID = -4013796607157549641L;

    public <T extends AnyTO> PropagationTasks(final PageReference pageReference, final String resource) {
        super(BaseModal.CONTENT_ID);

        final MultilevelPanel mlp = new MultilevelPanel("tasks");
        add(mlp);

        mlp.setFirstLevel(new PropagationTaskSearchResultPanel(FIRST_LEVEL_ID, resource, pageReference) {

            private static final long serialVersionUID = -2195387360323687302L;

            @Override
            protected void viewTask(final PropagationTaskTO taskTO, final AjaxRequestTarget target) {
                mlp.next("task.view", new TaskExecutionDetails<PropagationTaskTO>(taskTO, pageReference), target);
            }
        });
    }
}

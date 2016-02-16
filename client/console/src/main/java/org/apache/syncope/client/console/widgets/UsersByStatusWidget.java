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
package org.apache.syncope.client.console.widgets;

import com.pingunaut.wicket.chartjs.chart.impl.Doughnut;
import com.pingunaut.wicket.chartjs.core.panel.DoughnutChartPanel;
import java.util.Map;
import org.apache.wicket.model.Model;

public class UsersByStatusWidget extends AbstractWidget {

    private static final long serialVersionUID = -816175678514035085L;

    private static final String[] COLORS = { "green", "orange", "aqua", "red", "gray" };

    public UsersByStatusWidget(final String id, final Map<String, Integer> usersByStatus) {
        super(id);

        Doughnut doughnut = new Doughnut();

        int i = 0;
        for (Map.Entry<String, Integer> entry : usersByStatus.entrySet()) {
            doughnut.getData().add(new LabeledDoughnutChartData(entry.getValue(), COLORS[i % 5], entry.getKey()));
            i++;
        }

        add(new DoughnutChartPanel("chart", Model.of(doughnut), MEDIUM_WIDTH, MEDIUM_HEIGHT));
    }

}

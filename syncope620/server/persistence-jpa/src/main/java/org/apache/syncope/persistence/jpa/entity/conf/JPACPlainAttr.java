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
package org.apache.syncope.persistence.jpa.entity.conf;

import java.util.ArrayList;
import java.util.List;
import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Table;
import javax.validation.Valid;
import org.apache.syncope.persistence.api.entity.Attributable;
import org.apache.syncope.persistence.api.entity.PlainAttrUniqueValue;
import org.apache.syncope.persistence.api.entity.PlainAttrValue;
import org.apache.syncope.persistence.api.entity.PlainSchema;
import org.apache.syncope.persistence.api.entity.conf.CPlainAttr;
import org.apache.syncope.persistence.api.entity.conf.CPlainAttrUniqueValue;
import org.apache.syncope.persistence.api.entity.conf.CPlainAttrValue;
import org.apache.syncope.persistence.api.entity.conf.CPlainSchema;
import org.apache.syncope.persistence.api.entity.conf.Conf;
import org.apache.syncope.persistence.jpa.entity.AbstractPlainAttr;

/**
 * Configuration attribute.
 */
@Entity
@Table(name = JPACPlainAttr.TABLE)
public class JPACPlainAttr extends AbstractPlainAttr implements CPlainAttr {

    private static final long serialVersionUID = 8022331942314540648L;

    public static final String TABLE = "CPlainAttr";

    /**
     * Auto-generated id for this table.
     */
    @Id
    private Long id;

    /**
     * The owner of this attribute.
     */
    @ManyToOne(fetch = FetchType.EAGER)
    private JPAConf owner;

    /**
     * The schema of this attribute.
     */
    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "schema_name")
    private JPACPlainSchema schema;

    /**
     * Values of this attribute (if schema is not UNIQUE).
     */
    @OneToMany(cascade = CascadeType.MERGE, orphanRemoval = true, mappedBy = "attribute")
    @Valid
    private List<JPACPlainAttrValue> values;

    /**
     * Value of this attribute (if schema is UNIQUE).
     */
    @OneToOne(cascade = CascadeType.ALL, mappedBy = "attribute")
    @Valid
    private JPACPlainAttrUniqueValue uniqueValue;

    /**
     * Default constructor.
     */
    public JPACPlainAttr() {
        super();
        values = new ArrayList<>();
    }

    @Override
    public Long getKey() {
        return id;
    }

    @Override
    public Conf getOwner() {
        return owner;
    }

    @Override
    public void setOwner(final Attributable<?, ?, ?> owner) {
        checkType(owner, JPAConf.class);
        this.owner = (JPAConf) owner;
    }

    @Override
    public CPlainSchema getSchema() {
        return schema;
    }

    @Override
    public void setSchema(final PlainSchema schema) {
        checkType(schema, JPACPlainSchema.class);
        this.schema = (JPACPlainSchema) schema;
    }

    @Override
    protected boolean addValue(final PlainAttrValue attrValue) {
        checkType(attrValue, JPACPlainAttrValue.class);
        return values.add((JPACPlainAttrValue) attrValue);
    }

    @Override
    public boolean removeValue(final PlainAttrValue attrValue) {
        checkType(attrValue, JPACPlainAttrValue.class);
        return values.remove((JPACPlainAttrValue) attrValue);
    }

    @Override
    public List<? extends CPlainAttrValue> getValues() {
        return values;
    }

    @Override
    public CPlainAttrUniqueValue getUniqueValue() {
        return uniqueValue;
    }

    @Override
    public void setUniqueValue(final PlainAttrUniqueValue uniqueValue) {
        checkType(owner, JPACPlainAttrUniqueValue.class);
        this.uniqueValue = (JPACPlainAttrUniqueValue) uniqueValue;
    }
}

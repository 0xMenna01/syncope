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
package org.apache.syncope.core.security;

import java.util.Arrays;
import org.apache.syncope.types.CipherAlgorithm;

/**
 * Command line version of encoder to encode the admin password
 */
public class EncodePasswordCLI {

    /**
     * @param args
     */
    public static void main(String[] args)
            throws Exception {

        if (args.length != 2) {
            usage();
            System.exit(0);
        }

        if (CipherAlgorithm.valueOf(args[1]).getAlgorithm().isEmpty()) {
            System.out.println("Unsupported algorithm " + args[1]);
            usage();
            System.exit(0);
        }

        System.out.println("Encoding password '" + args[0] + "' with " + args[1]);
        System.out.println(PasswordEncoder.encodePassword(args[0], CipherAlgorithm.valueOf(args[1])));
    }

    private static void usage() {
        System.out.println("Usage: EncodePassword <password> <algorithm>");
        System.out.println("Supported algorithms:" + Arrays.toString(CipherAlgorithm.values()));
    }
}

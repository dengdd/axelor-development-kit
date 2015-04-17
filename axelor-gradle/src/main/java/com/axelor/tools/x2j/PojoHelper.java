/**
 * Axelor Business Solutions
 *
 * Copyright (C) 2005-2014 Axelor (<http://axelor.com>).
 *
 * This program is free software: you can redistribute it and/or  modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package com.axelor.tools.x2j;

import java.io.InputStream;
import java.io.InputStreamReader;

import com.axelor.common.ClassUtils;
import com.google.common.io.CharStreams;

public class PojoHelper {
    private static final String RESERVED_WORDS_FILE = "reserved-words.txt";

    private static String[] reservedWords;

    static {
        try (InputStream is = ClassUtils.getResourceStream(RESERVED_WORDS_FILE)) {
            reservedWords = CharStreams.toString(new InputStreamReader(is)).split("\n");
        } catch (Exception e) {
            reservedWords = new String[0];
        }
    }

    public static boolean isReservedWords(String name) {
        if (name == null) {
            return false;
        }

        for (String word : reservedWords) {
            if (name.equalsIgnoreCase(word.trim())) {
                return true;
            }
        }
        return false;
    }
}

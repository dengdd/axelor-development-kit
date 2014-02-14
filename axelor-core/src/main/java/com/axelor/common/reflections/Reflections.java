/**
 * Copyright (c) 2012-2014 Axelor. All Rights Reserved.
 *
 * The contents of this file are subject to the Common Public
 * Attribution License Version 1.0 (the "License"); you may not use
 * this file except in compliance with the License. You may obtain a
 * copy of the License at:
 *
 * http://license.axelor.com/.
 *
 * The License is based on the Mozilla Public License Version 1.1 but
 * Sections 14 and 15 have been added to cover use of software over a
 * computer network and provide for limited attribution for the
 * Original Developer. In addition, Exhibit A has been modified to be
 * consistent with Exhibit B.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * The Original Code is part of "Axelor Business Suite", developed by
 * Axelor exclusively.
 *
 * The Original Developer is the Initial Developer. The Initial Developer of
 * the Original Code is Axelor.
 *
 * All portions of the code written by Axelor are
 * Copyright (c) 2012-2014 Axelor. All Rights Reserved.
 */
package com.axelor.common.reflections;

/**
 * The {@link Reflections} utilities provides fast and easy way to search for
 * resources and types.
 * 
 */
public final class Reflections {

	private Reflections() {
	}

	/**
	 * Return a {@link ClassFinder} to search for the sub types of the given
	 * type.
	 * 
	 * @param type
	 *            the super type
	 * @return an instance of {@link ClassFinder}
	 */
	public static <T> ClassFinder<T> findSubTypesOf(Class<T> type) {
		return new ClassFinder<>(type);
	}

	/**
	 * Return a {@link ClassFinder} to search for types.
	 * 
	 * @return an instance of {@link ClassFinder}
	 */
	public static ClassFinder<?> findTypes() {
		return findSubTypesOf(Object.class);
	}

	/**
	 * Return a {@link ResourceFinder} to search for resources.
	 * 
	 * @return an instance of {@link ResourceFinder}
	 */
	public static ResourceFinder findResources() {
		return new ResourceFinder();
	}
}
/*-
 * #%L
 * io.netty.util.internal.cert
 * %%
 * Copyright (C) 2018 - 2019 Paremus Ltd
 * %%
 * Licensed under the Fair Source License, Version 0.9 (the "License");
 *
 * See the NOTICE.txt file distributed with this work for additional
 * information regarding copyright ownership. You may not use this file
 * except in compliance with the License. For usage restrictions see the
 * LICENSE.txt file distributed with this work
 * #L%
 */
package io.netty.util.internal.cert.domain;

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@ObjectClassDefinition
public @interface Config {
  @AttributeDefinition(
      required = false,
      description = "The folder to store security domain information")
  String storage_folder() default "";
}

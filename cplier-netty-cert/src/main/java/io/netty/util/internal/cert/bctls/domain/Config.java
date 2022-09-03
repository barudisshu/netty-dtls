package io.netty.util.internal.cert.bctls.domain;

import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;

@ObjectClassDefinition
public @interface Config {
  @AttributeDefinition(
      required = false,
      description = "The folder to store security domain information")
  String storage_folder() default "";
}

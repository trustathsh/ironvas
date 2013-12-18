#!/bin/sh

VERSION=${pom.version}

CLASSPATH=".:"\
"original-ironvas-$VERSION.jar:"\
"lib/httpcore-4.1.1.jar:"\
"lib/ifmapj-0.1.4.jar:"\
"lib/scala-library-2.9.0.jar"

/usr/bin/java -classpath $CLASSPATH  de.hshannover.f4.trust.ironvas.Ironvas

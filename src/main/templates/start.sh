#!/bin/sh

CLASSPATH=".:"\
"original-ironvas-0.0.6.jar:"\
"lib/httpcore-4.1.1.jar:"\
"lib/ifmapj-0.1.4.jar:"\
"lib/scala-library-2.9.0.jar"

/usr/bin/java -classpath $CLASSPATH  de.fhhannover.inform.trust.ironvas.Ironvas

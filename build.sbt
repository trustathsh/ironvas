import AssemblyKeys._

name := "ironvas"

version := "0.0.5"

organization := "de.fhhannover.inform.trust"

libraryDependencies ++= Seq(
		"de.fhhannover.inform.trust" % "ifmapj" % "0.1.4",
		"junit" % "junit" % "4.10" % "test",
		"org.mockito" % "mockito-all" % "1.9.0" % "test",
		"com.novocode" % "junit-interface" % "0.8" % "test"
)


// append several options to the list of options passed to the Java compiler
javacOptions ++= Seq("-source", "1.6", "-target", "1.6")

// set the main class for packaging the main jar
// 'run' will still auto-detect and prompt
// change Compile to Test to set it for the test jar
mainClass in (Compile, packageBin) := Some("de.fhhannover.inform.trust.ironvas.Ironvas")

// set the main class for the main 'run' task
// change Compile to Test to set it for 'test:run'
mainClass in (Compile, run) := Some("de.fhhannover.inform.trust.ironvas.Ironvas")

resolvers += "Local Maven Repository" at "file://"+Path.userHome.absolutePath+"/.m2/repository"

assemblySettings

jarName in assembly := "ironvas.jar"



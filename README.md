ironvas
=======
ironvas is a *highly experimental* integration of Open Vulnerability
Assessment System ([OpenVAS] [1]) into a MAP-Infrastructure. The integration
aims to share security related informations (vulnerabilities
detected by OpenVAS) with other network components in the [TNC architecture] [2]
via IF-MAP.

ironvas consists of two elements:

* One part - the "publisher" - simply fetches the latest scan reports stored in
  an OpenVAS server, converts them into IF-MAP metadata
  (currently "event"-metadata) and finally publishes them into a MAP server.
  ironvas takes care to not flood the MAPS with
  redundant information, furthermore you can specify a filter (in `filter.js`)
  for the vulnerabilities to publish.
  If a scan report is deleted from the OpenVAS server, ironvas will purge all
  published metadata, associated with the deleted report, from the MAPS.
  In other words this means that ironvas always tries to reflect the current/latest
  knowledge of an OpenVAS server in a MAP server.
  The event-metadata that ironvas published is filled with the following
  values from the scan reports:
  - the name of the vulnerability
  - the time it was discovered
  - the id of the discoverer (OpenVAS server)
  - the magnitude of the vulnerability
  - the significance
  - the event-type == CVE
  - CVE information
  - and the corresponding URIs for the CVE entries

* The second, more experimental, part of ironvas - the "subscriber" - goes the
  other way around.
  It will subscribe for "request-for-investigation"-metadata of a PDP in the MAPS.
  If the PDP publish those metadata to an IP address, ironvas schedules a new
  scan task for that IP address in OpenVAS. If the scan produces new
  vulnerability information they are collected by the "publisher" as described
  above.
  If the PDP removes the "request-for-investigation"-metadata from the IP
  address, ironvas also removes the scan task (and with it the report) from
  OpenVAS.

ironvas is [avaiable][3] in two versions, the binary package (`ironvas-x.x.x-bin.zip`)
is ready to run, all you need is to configure it to your needs.
If you like to build ironvas by your own you can use the source package
(`ironvas-x.x.x-src.zip`) or the latest code from the [GitHub repository][githubrepo].


Requirements
============
To use the binary package of ironvas you need the following components:

* OpenJDK Version 1.6 or higher
* OpenVAS-4 or higher
* MAP server implementation (e.g. [irond] [3])
* [ifmapj] [3]

If you have downloaded the source code and want to build ironvas by
yourself Maven 3 is also needed.


Configuration
=============
To setup the binary package you need to import the OpenVAS and MAP server
certificates into `ironvas.jks`.
On a Ubuntu installation of OpenVAS you can find the OpenVAS certificate in
`/var/lib/openvas/CA/servercert.pem`. If you want to use ironvas with irond
the keystores of both are configured with ready-to-use testing certificates.

The remaining configuration parameters can be done through the
`configuration.properties` file in the ironvas package.
In general you have to specify:

* the OpenVAS server IP address,
* the OpenVAS OMP port,
* the OpenVAS OMP credentials,
* the MAPS URL and credentials.

Have a look at the comments in `configuration.properties` for more details.


Building
========
Before you can build ironvas (if you have downloaded the source code)
you need to install ifmapj version 0.1.4 in your local Maven
repository. To do so download ifmapj from the [Trust@FHH website] [3], unzip it
and execute

	$ mvn install

to have it avaiable.

Now you can build ironvas, simply execute:

	$ mvn package

in the root directory of the ironvas project.
Maven should download all further needed dependencies for you. After a successful
build you should find the `ironvas-x.x.x.jar` in the `target` sub-directory.

**Note** that the `package` phase creates a single executable JAR of ironvas. To
include a `ironvas.jks` and a `configuration.properties` in this JAR file place
both files in `src/main/resources` before executing the `package` phase.


Running
=======
To run the binary package of ironvas simply execute:

	$ ./start.sh

The resulting JAR of the `package` phase can be started with:

	$ java -jar ironvas-x.x.x.jar


Feedback
========
If you have any questions, problems or comments, please contact
	<trust@f4-i.fh-hannover.de>


LICENSE
=======
ironvas is licensed under the [Apache License, Version 2.0] [4].


Note
====

ironvas is an experimental prototype and is not suitable for actual use. The Scala code is not
really idiomatic Scala, but some kind of learning-experiment.

Feel free to fork/contribute.


[1]: http://www.openvas.org
[2]: http://www.trustedcomputinggroup.org/developers/trusted_network_connect
[3]: https://trust.inform.fh-hannover.de/joomla/index.php/downloads
[4]: http://www.apache.org/licenses/LICENSE-2.0.html
[githubrepo]: https://github.com/trustatfhh/ironvas

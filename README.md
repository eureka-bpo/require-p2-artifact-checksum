
Example of usage.

from pom.xml:

```xml
	<dependencies>
		...
		<dependency>
			<groupId>org.eclipse.ide</groupId>
			<artifactId>org.eclipse.core.jobs</artifactId>
			<version>3.15.0.v20230808-1403</version>
		</dependency>
		...
	</dependencies>

	<repositories>
		...
		<repository>
			<id>eclipse-2023-09</id>
			<url>https://p2repository.com/mvn3/eclipse-2023-09/</url>
		</repository>
		...
	</repositories>

	<build>
		<plugins>
			...
			<plugin>
				<artifactId>maven-enforcer-plugin</artifactId>
				<executions>
					<execution>
						<id>enforce-p2-checksums</id>
						<phase>package</phase>
						<goals>
							<goal>enforce</goal>
						</goals>
						<configuration>
							<rules>
								<requireP2ArtifactChecksum>
									<repositoryId>eclipse-2023-09</repositoryId>
									<originalUrl>https://download.eclipse.org/releases/2023-09/202309131000/</originalUrl>
								</requireP2ArtifactChecksum>
							</rules>
						</configuration>
					</execution>
				</executions>
				<dependencies>
					<dependency>
						<groupId>eu.eureka-bpo.maven</groupId>
						<artifactId>require-p2-artifact-checksum</artifactId>
						<version>SNAPSHOT</version>
					</dependency>
				</dependencies>
			</plugin>
			...
		</plugins>
	</build>

```

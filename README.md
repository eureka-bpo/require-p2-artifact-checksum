## requireP2ArtifactChecksum

This project presents custom rule requireP2ArtifactChecksum for [maven-enforcer-plugin](https://maven.apache.org/enforcer/maven-enforcer-plugin/index.html)

#### Purpose

requireP2ArtifactChecksum is meant for validation of checksums of artifacts from p2 repositories. This validation is useful, when artifacts are received indirectly from 3d-party services (like [p2repository.com](https://www.p2repository.com/)).

#### Minimum requirements
- Java 17
- Maven 3.6.3
- Maven Enforcer Plugin 3.2.1

#### Usage

Example of usage.

Add such declaration to your pom.xml:

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

Some notes ot example
1. repositories.repository.id and requireP2ArtifactChecksum.repositoryId must have the same value (```eclipse-2023-09``` here)
2. requireP2ArtifactChecksum is not a built-in rule, it must be declared separately (block ```dependencies``` in maven-enforcer-plugin declaration)

package eu.eurekabpo.maven.enforcer.rules;

import javax.inject.Inject;
import javax.inject.Named;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import aQute.bnd.http.HttpClient;
import aQute.bnd.osgi.Processor;
import aQute.p2.api.Artifact;
import aQute.p2.api.ArtifactProvider;
import aQute.p2.packed.Unpack200;
import aQute.p2.provider.P2Impl;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.io.FileUtils;
import org.apache.maven.enforcer.rule.api.AbstractEnforcerRule;
import org.apache.maven.enforcer.rule.api.EnforcerRuleError;
import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.apache.maven.project.MavenProject;

/**
 * Rule to validate a p2 artifacts to match the specified checksum.
 *
 */
@Named("requireP2ArtifactChecksum")
public class RequireP2ArtifactChecksum extends AbstractEnforcerRule {

    @Setter @Getter
    private String repositoryId;
    @Setter @Getter
    private String originalUrl;
    @Inject
    private MavenProject project;

    @Override
    public void execute() throws EnforcerRuleException {
        if (this.originalUrl == null) {
            throw new EnforcerRuleError("P2 Repository URL unspecified");
        }
        if (this.repositoryId == null) {
            throw new EnforcerRuleError("Repository id unspecified");
        }
        if (project.getRepositories().stream().noneMatch(repo -> Objects.equals(repo.getId(), repositoryId))) {
            throw new EnforcerRuleError("Specified P2 Repository id (" + repositoryId +
                ") does not match with any declared repository " +
                project.getRepositories().stream().map( repo -> repo.getId()).collect(Collectors.toList()));
        }

        Set<org.apache.maven.artifact.Artifact> mavenArtifacts = project.getArtifacts();
        if (!mavenArtifacts.isEmpty()) {
            getLog().debug(() -> "Maven project has " + mavenArtifacts.size() + " artifacts: " +
                mavenArtifacts.stream().map(a -> String.join(":", a.getGroupId(),
                    a.getArtifactId(), a.getVersion())).collect(Collectors.joining(", ")));
            try {
                List<Artifact> p2Artifacts = getP2ArtifactList();
                getLog().debug(() -> "P2 Repository (" + originalUrl + ") has " + p2Artifacts.size() +
                    " artifacts: " + p2Artifacts.stream().map(a -> String.join(":", a.id, a.version.toString()))
                    .collect(Collectors.joining(", ")));
                validateChecksums(mavenArtifacts, p2Artifacts);
            } catch (Exception e) {
                getLog().error("Error has acquired: " + e.getMessage());
            }
        } else {
            getLog().debug(() -> "There are no dependencies from P2 Repository id " + repositoryId);
        }
    }

    private List<Artifact> getP2ArtifactList() throws Exception {
        ArtifactProvider provider = new P2Impl(new Unpack200(), new HttpClient(), URI.create(originalUrl), Processor.getPromiseFactory());
        return provider.getBundles();
    }
    
    private MessageDigest md5Digest;
    private boolean md5DigestInitialized;
    private MessageDigest getMd5MessageDigest() {
        if (!md5DigestInitialized) {
            try {
                md5Digest = MessageDigest.getInstance("MD5");
            } catch (NoSuchAlgorithmException e) {
                getLog().warn("Calculating MD5 checksum is not possible: " + e.getMessage());
            }
            md5DigestInitialized = true;
        }
        return md5Digest;
    }

    private String calculateChecksum(MessageDigest digest, byte[] mavenFileContent) {
        byte[] digestBytes = new byte[0];
        synchronized (digest) {
            digest.reset();
            digest.update(mavenFileContent);
            digestBytes = digest.digest();
        }
        return bytesToString(digestBytes);
    }

    private String bytesToString(byte[] checksum) {
        StringBuilder sb = new StringBuilder();
        for (byte b : checksum) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString().toLowerCase();
    }

    private void validateChecksums(Collection<org.apache.maven.artifact.Artifact> mavenArtifacts, List<Artifact> p2Artifacts) throws EnforcerRuleException {
        List<EnforcerRuleException> exceptions = new ArrayList<>();
        for (org.apache.maven.artifact.Artifact mavenArtifact : mavenArtifacts) {
            String artifactId = mavenArtifact.getArtifactId();
            String artifactVersion = mavenArtifact.getVersion();
            File mavenFile = mavenArtifact.getFile();
            if (mavenFile == null || !mavenFile.exists()) {
                getLog().info(() -> "Maven artifact " + String.join(":", artifactId, artifactVersion) + 
                    " file is not found and cannot be checked");
                continue;
            }
            Artifact p2Artifact = p2Artifacts.parallelStream()
                .filter(p2a -> Objects.equals(artifactId, p2a.id) && Objects.equals(artifactVersion, p2a.version.toString()))
                .findAny().orElse(null);
            if (p2Artifact != null) {
                getLog().debug(() -> "For Maven artifact " + String.join(":", mavenArtifact.getGroupId(), mavenArtifact.getArtifactId(), mavenArtifact.getVersion()) + 
                    " P2 artifact " + String.join(":", p2Artifact.id, p2Artifact.version.toString()) + " has found");
                byte[] mavenFileContent;
                try {
                    mavenFileContent = FileUtils.readFileToByteArray(mavenFile);
                } catch (IOException e) {
                    getLog().warn(() -> "Error has acquired while reading file " + mavenFile.getAbsolutePath() + " of Maven artifact " +
                        String.join(":", mavenArtifact.getGroupId(), mavenArtifact.getArtifactId(), mavenArtifact.getVersion()));
                    continue;
                }
                try {
                    MessageDigest digest;
                    if (p2Artifact.md5 != null && (digest = getMd5MessageDigest()) != null) {
                        String calculatedChecksum = calculateChecksum(digest, mavenFileContent);
                        if (!p2Artifact.md5.equalsIgnoreCase(calculatedChecksum)) {
                            throw new EnforcerRuleException("Checksums are not equal for artifact " + 
                                mavenArtifact.getGroupId() + ":" + artifactId + ":" + artifactVersion + 
                                ". Original MD5 is " + p2Artifact.md5 +
                                ", but calculated MD5 is " + calculatedChecksum);
                        }
                        getLog().debug(() -> "MD5 has compared and found equal");
                    } else {
                        getLog().info("Cannot check checksum for artifact " +
                                        String.join(":", mavenArtifact.getGroupId(), artifactId, artifactVersion));
                    }
                } catch (EnforcerRuleException e) {
                    exceptions.add(e);
                }
            } else {
                getLog().info("Cannot found p2 repository data for artifact " +
                    String.join(":", mavenArtifact.getGroupId(), artifactId, artifactVersion));
            }
        }
        if (!exceptions.isEmpty()) {
            String message = exceptions.stream().map(ex -> ex.getMessage()).collect(Collectors.joining(System.lineSeparator()));
            throw new EnforcerRuleException(message);
        }
    }

    @Override
    public String toString() {
        return "RequireP2ArtifactChecksum [repositoryId=" + repositoryId + ", originalUrl=" + originalUrl + "]";
    }
}

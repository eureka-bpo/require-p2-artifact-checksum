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
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
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
import org.apache.maven.RepositoryUtils;
import org.apache.maven.enforcer.rule.api.AbstractEnforcerRule;
import org.apache.maven.enforcer.rule.api.EnforcerRuleError;
import org.apache.maven.enforcer.rule.api.EnforcerRuleException;
import org.apache.maven.execution.MavenSession;
import org.apache.maven.project.MavenProject;
import org.eclipse.aether.RepositorySystem;
import org.eclipse.aether.repository.RemoteRepository;
import org.eclipse.aether.resolution.ArtifactRequest;
import org.eclipse.aether.resolution.ArtifactResolutionException;
import org.eclipse.aether.resolution.ArtifactResult;

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
    @Inject
    private MavenSession session;
    @Inject
    private RepositorySystem repositorySystem;

    @Override
    public void execute() throws EnforcerRuleException {
        if (this.originalUrl == null) {
            throw new EnforcerRuleError("P2 Original Repository URL unspecified");
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
        if (mavenArtifacts.isEmpty()) {
            getLog().debug(() -> "Project has no dependencies");
            return;
        }
        Collection<org.apache.maven.artifact.Artifact> mavenArtifactsFromP2Repository = filterMavenArtifacts(mavenArtifacts);
        if (mavenArtifactsFromP2Repository.isEmpty()) {
            getLog().debug(() -> "There are no dependencies from P2 Repository " + repositoryId);
            return;
        }
        getLog().debug(() -> "Maven project has " + mavenArtifactsFromP2Repository.size() + " artifacts from P2 repository " +
            repositoryId + ": " + mavenArtifactsFromP2Repository.stream().map(this::toString).collect(Collectors.joining(", ")));
        List<Artifact> tmpP2Artifacts = Collections.emptyList();
        try {
            tmpP2Artifacts = getP2ArtifactList();
            if (tmpP2Artifacts == null || tmpP2Artifacts.isEmpty()) {
                throw new Exception("P2 artifacts are not found on URL " + originalUrl);
            }
        } catch (Exception e) {
            getLog().error("Error has occured: " + e.getMessage());
            throw new EnforcerRuleError("Error has occured while reading artifacts list from " + originalUrl);
        }
        List<Artifact> p2Artifacts = tmpP2Artifacts;
        getLog().debug(() -> "P2 Repository (" + originalUrl + ") has " + p2Artifacts.size() +
            " artifacts: " + p2Artifacts.stream().map(this::toString)
            .collect(Collectors.joining(", ")));
        validateMavenArtifacts(mavenArtifactsFromP2Repository, p2Artifacts);
    }

    private Collection<org.apache.maven.artifact.Artifact> filterMavenArtifacts(Collection<org.apache.maven.artifact.Artifact> srcArtifacts) {
        Collection<org.apache.maven.artifact.Artifact> fromP2 = new ArrayList<>();
        List<RemoteRepository> repository = project.getRemoteProjectRepositories().stream().filter(repo -> repositoryId.equals(repo.getId())).collect(Collectors.toList());
        srcArtifacts.forEach( srcArtifact -> {
            ArtifactRequest request = new ArtifactRequest(RepositoryUtils.toArtifact(srcArtifact), repository, null);
            try {
                ArtifactResult result = repositorySystem.resolveArtifact(session.getRepositorySession(), request);
                fromP2.add(RepositoryUtils.toArtifact(result.getArtifact()));
            } catch (ArtifactResolutionException e) {
                getLog().debug(() -> "Maven artifact " + toString(srcArtifact) + " has not found in repository " + repositoryId);
            }
        });
        return fromP2;
    }

    private List<Artifact> getP2ArtifactList() throws Exception {
        ArtifactProvider provider = new P2Impl(new Unpack200(), new HttpClient(), URI.create(originalUrl), Processor.getPromiseFactory());
        return provider.getBundles();
    }

    private String calculateChecksum(String algorithm, byte[] mavenFileContent) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        digest.update(mavenFileContent);
        byte[] digestBytes = digest.digest();
        return bytesToString(digestBytes);
    }

    private String bytesToString(byte[] checksum) {
        StringBuilder sb = new StringBuilder();
        for (byte b : checksum) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString().toLowerCase();
    }

    @SuppressWarnings( "serial" )
    private static final Map<Function<Artifact, String>, String> artifactChecksumProperty2Algorithm =
        Collections.unmodifiableMap(new LinkedHashMap<Function<Artifact, String>, String>() {{
            this.put(a -> a.sha512, "SHA-512");
            this.put(a -> a.sha256, "SHA-256");
            this.put(a -> a.sha1,   "SHA-1");
            this.put(a -> a.md5,    "MD5");
        }});

    private void validateMavenArtifacts(Collection<org.apache.maven.artifact.Artifact> mavenArtifacts, List<Artifact> p2Artifacts) throws EnforcerRuleException {
        List<EnforcerRuleException> exceptions = Collections.synchronizedList(new ArrayList<>());
        AtomicInteger checked = new AtomicInteger();
        AtomicInteger unchecked = new AtomicInteger();
        mavenArtifacts.forEach(mavenArtifact -> {
            try {
                Boolean validationResult = validateMavenArtifact(mavenArtifact, p2Artifacts);
                if (validationResult != null && validationResult.booleanValue()) {
                    checked.incrementAndGet();
                } else if (validationResult != null && !validationResult.booleanValue()) {
                    unchecked.incrementAndGet();
                }
            } catch (EnforcerRuleException e) {
                exceptions.add(e);
            }
        });
        if (!exceptions.isEmpty()) {
            String message = "For " + exceptions.size() + " artifacts checksums are not equal: " + System.lineSeparator() +
                exceptions.stream().map(ex -> ex.getMessage()).collect(Collectors.joining(System.lineSeparator()));
            throw new EnforcerRuleException(message);
        } else {
            getLog().info("Checksums analysis has been correctly finished: " + checked.get() + " artifacts have correct checksums, " +
                unchecked.get() + " artifacts have no checksum information");
        }
    }

    /**
     * @return
     *     - true if checksum is valid,
     *     - false if checksum is not valid,
     *     - null if checksum validation is impossible
     * */
    private Boolean validateMavenArtifact(org.apache.maven.artifact.Artifact mavenArtifact, List<Artifact> p2Artifacts) throws EnforcerRuleException {
        File mavenFile = mavenArtifact.getFile();
        if (mavenFile == null || !mavenFile.exists()) {
            getLog().info(() -> "Maven artifact " + toString(mavenArtifact) + " file is not found and cannot be checked");
            return null;
        }
        String artifactId = mavenArtifact.getArtifactId();
        String artifactVersion = mavenArtifact.getVersion();
        Artifact p2Artifact = p2Artifacts.parallelStream()
            .filter(p2a -> Objects.equals(artifactId, p2a.id) && Objects.equals(artifactVersion, p2a.version.toString()))
            .findAny().orElse(null);
        if (p2Artifact != null) {
            getLog().debug(() -> "For Maven artifact " + toString(mavenArtifact) + " P2 artifact " + toString(p2Artifact) + " has found");
            byte[] mavenFileContent;
            try {
                mavenFileContent = FileUtils.readFileToByteArray(mavenFile);
            } catch (IOException e) {
                getLog().warn(() -> "Error has acquired while reading file " + mavenFile.getAbsolutePath() + " of Maven artifact " +
                    toString(mavenArtifact));
                return null;
            }
            try {
                for (Map.Entry<Function<Artifact, String>, String> entry : artifactChecksumProperty2Algorithm.entrySet()) {
                    String p2ArtifactChecksum = entry.getKey().apply(p2Artifact);
                    if (p2ArtifactChecksum != null) {
                        String calculatedChecksum = calculateChecksum(entry.getValue(), mavenFileContent);
                        if (!p2ArtifactChecksum.equalsIgnoreCase(calculatedChecksum)) {
                            throw new EnforcerRuleException("Checksums are not equal for artifact " + 
                                mavenArtifact.getGroupId() + ":" + artifactId + ":" + artifactVersion + 
                                ". Original " + entry.getValue() + " is " + p2ArtifactChecksum +
                                ", but calculated " + entry.getValue() + " is " + calculatedChecksum);
                        }
                        getLog().debug(() -> entry.getValue() + " has compared and found equal");
                        return true;
                    }
                }
                getLog().info("Cannot check checksum for artifact " +
                    toString(mavenArtifact) + " while p2 artifact has no checksum info");
                return false;
            } catch (NoSuchAlgorithmException e) {
                getLog().info(() -> "Cannot check checksum for artifact " +
                    toString(mavenArtifact) + " while error has occured: " + e.getMessage());
                return false;
            }
        } else {
            getLog().info("Cannot found p2 repository data for artifact " + toString(mavenArtifact));
            return null;
        }
    }

    private String toString(org.apache.maven.artifact.Artifact artifact) {
        return String.join(":", artifact.getGroupId(), artifact.getArtifactId(), artifact.getVersion());
    }

    private String toString(Artifact artifact) {
        return String.join(":", artifact.id, artifact.version.toString());
    }

    @Override
    public String toString() {
        return "RequireP2ArtifactChecksum [repositoryId=" + repositoryId + ", originalUrl=" + originalUrl + "]";
    }
}

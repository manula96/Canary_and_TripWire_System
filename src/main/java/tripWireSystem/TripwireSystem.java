package tripWireSystem;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.*;
import java.util.logging.*;
import alertSystem.EmailAlert; // Importing the EmailAlert class from alertSystem package

public class TripwireSystem {
    private static final List<String> MONITORED_PATHS = Arrays.asList(
            "C:\\Manula\\Academics\\Master in Cyber Security\\Sem 4\\Project\\Codebase\\COMP6900_Canary\\src\\test\\java\\TripWireFil1",
            "C:\\Manula\\Academics\\Master in Cyber Security\\Sem 4\\Project\\Codebase\\COMP6900_Canary\\src\\test\\java\\TripWireFil2",
            "C:\\Manula\\Academics\\Master in Cyber Security\\Sem 4\\Project\\Codebase\\COMP6900_Canary\\src\\test\\java\\TripWireFolder"
    ); // Replace with actual file and folder paths
    private static final Logger logger = Logger.getLogger(TripwireSystem.class.getName());
    private static final Map<String, String> originalHashes = new HashMap<>();

    public static void main(String[] args) {
        try {
            // Initialize the original checksums for all monitored files
            initializeChecksums(MONITORED_PATHS);

            // Start watching for changes in all monitored files and folders
            watchForChanges(MONITORED_PATHS);
        } catch (Exception e) {
            logger.severe("Error in tripwire system: " + e.getMessage());
        }
    }

    // Initialize checksums for all monitored files and folders
    public static void initializeChecksums(List<String> paths) throws IOException, NoSuchAlgorithmException {
        for (String path : paths) {
            File file = new File(path);
            if (file.isFile()) {
                originalHashes.put(path, getFileChecksum(path));
            } else if (file.isDirectory()) {
                // If it's a folder, initialize checksums for all files in the folder
                Files.walk(Paths.get(path)).filter(Files::isRegularFile).forEach(filePath -> {
                    try {
                        originalHashes.put(filePath.toString(), getFileChecksum(filePath.toString()));
                    } catch (Exception e) {
                        logger.warning("Failed to initialize checksum for file: " + filePath);
                    }
                });
            }
        }
    }

    // Watch for changes in files and folders
    public static void watchForChanges(List<String> paths) throws IOException, InterruptedException, NoSuchAlgorithmException {
        WatchService watchService = FileSystems.getDefault().newWatchService();
        Map<WatchKey, Path> watchKeys = new HashMap<>();

        // Register all parent directories of monitored files and folders
        for (String path : paths) {
            Path parentPath = Paths.get(path).getParent();
            if (!watchKeys.containsValue(parentPath)) {
                WatchKey key = parentPath.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_DELETE);
                watchKeys.put(key, parentPath);
            }
        }

        WatchKey key;
        while ((key = watchService.take()) != null) {
            Path dir = watchKeys.get(key);
            for (WatchEvent<?> event : key.pollEvents()) {
                WatchEvent.Kind<?> kind = event.kind();
                Path eventPath = dir.resolve((Path) event.context()).toAbsolutePath();

                // If the event is on a file we're monitoring, check for modifications
                if (originalHashes.containsKey(eventPath.toString())) {
                    if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {
                        String newHash = getFileChecksum(eventPath.toString());
                        String originalHash = originalHashes.get(eventPath.toString());

                        if (!originalHash.equals(newHash)) {
                            logger.warning("ALERT: Unauthorized modification detected in file: " + eventPath);
                            originalHashes.put(eventPath.toString(), newHash); // Update hash for further checks
                            // Trigger email alert on unauthorized file modification
                            EmailAlert.sendEmailAlert(eventPath.toString(), "modified");
                        }
                    } else if (kind == StandardWatchEventKinds.ENTRY_DELETE) {
                        logger.warning("ALERT: File deleted: " + eventPath);
                        originalHashes.remove(eventPath.toString());  // Remove from hash map
                        EmailAlert.sendEmailAlert(eventPath.toString(), "deleted");
                    } else if (kind == StandardWatchEventKinds.ENTRY_CREATE) {
                        logger.warning("ALERT: New file created: " + eventPath);
                        String newHash = getFileChecksum(eventPath.toString());
                        originalHashes.put(eventPath.toString(), newHash);  // Add new file's hash
                        EmailAlert.sendEmailAlert(eventPath.toString(), "created");
                    }
                }
            }
            key.reset();
        }
    }

    // Generate SHA-256 checksum for a file
    public static String getFileChecksum(String filePath) throws IOException, NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream fis = new FileInputStream(filePath)) {
            byte[] byteArray = new byte[1024];
            int bytesCount;
            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
        }
        byte[] bytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

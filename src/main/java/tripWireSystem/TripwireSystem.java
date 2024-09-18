package tripWireSystem;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.util.logging.*;
import alertSystem.EmailAlert; // Importing the EmailAlert class from alertSystem package

public class TripwireSystem {
    private static final String MONITORED_FILE_PATH = "/path/to/monitored/file.txt"; // Replace with the actual file path
    private static final Logger logger = Logger.getLogger(TripwireSystem.class.getName());
    private static String originalHash;

    public static void main(String[] args) {
        try {
            // Initialize the original checksum for the monitored file
            originalHash = getFileChecksum(MONITORED_FILE_PATH);

            // Start watching the monitored file
            watchForFileChanges(MONITORED_FILE_PATH);
        } catch (Exception e) {
            logger.severe("Error in tripwire system: " + e.getMessage());
        }
    }

    public static void watchForFileChanges(String filePath) throws IOException, InterruptedException, NoSuchAlgorithmException {
        WatchService watchService = FileSystems.getDefault().newWatchService();
        Path path = Paths.get(filePath).getParent();
        path.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY);

        WatchKey key;
        while ((key = watchService.take()) != null) {
            for (WatchEvent<?> event : key.pollEvents()) {
                if (event.context().toString().equals(new File(filePath).getName())) {
                    String newHash = getFileChecksum(filePath);
                    if (!originalHash.equals(newHash)) {
                        logger.warning("ALERT: Unauthorized modification detected in file: " + filePath);
                        originalHash = newHash; // Update hash for further checks
                        // Trigger email alert on unauthorized file modification
                        EmailAlert.sendEmailAlert();
                    }
                }
            }
            key.reset();
        }
    }

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

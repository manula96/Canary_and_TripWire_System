package canarySystem;

import alertSystem.EmailAlert;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.logging.*;
import java.util.concurrent.TimeUnit;

public class CanaryFileSystem {
    private static final String CANARY_FOLDER_PATH = "C:\\Manula\\Academics\\Master in Cyber Security\\Sem 4\\Project\\Codebase\\COMP6900_Canary\\src\\test\\java\\Important Folder"; // Replace with the actual folder path
    private static final Logger logger = Logger.getLogger(CanaryFileSystem.class.getName());
    private static long lastAccessTime = -1;

    public static void main(String[] args) {
        try {
            // Start monitoring the folder
            watchCanaryFolder(CANARY_FOLDER_PATH);
        } catch (Exception e) {
            logger.severe("Error in canary folder monitoring system: " + e.getMessage());
        }
    }

    public static void watchCanaryFolder(String folderPath) throws IOException, InterruptedException {
        WatchService watchService = FileSystems.getDefault().newWatchService();
        Path path = Paths.get(folderPath);
        path.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_DELETE);

        logger.info("Monitoring folder: " + folderPath);

        // Initial access time check
        lastAccessTime = getLastAccessTime(folderPath);

        WatchKey key;
        while (true) {
            // Poll for file system events
            key = watchService.poll(500, TimeUnit.MILLISECONDS); // Polling interval of 500ms for responsiveness

            if (key != null) {
                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();
                    Path fileName = (Path) event.context();

                    if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {
                        logger.warning("ALERT: File modified: " + fileName);
                        EmailAlert.sendEmailAlert(); // Trigger email alert on file modification
                    } else if (kind == StandardWatchEventKinds.ENTRY_CREATE) {
                        logger.warning("ALERT: New file created: " + fileName);
                        EmailAlert.sendEmailAlert(); // Trigger email alert on file creation
                    } else if (kind == StandardWatchEventKinds.ENTRY_DELETE) {
                        logger.warning("ALERT: File deleted: " + fileName);
                        EmailAlert.sendEmailAlert(); // Trigger email alert on file deletion
                    }
                }
                key.reset();
            }

            // Check if the folder was accessed (even without modification)
            long currentAccessTime = getLastAccessTime(folderPath);
            if (currentAccessTime != lastAccessTime) {
                logger.warning("ALERT: Folder accessed without modification");
                EmailAlert.sendEmailAlert(); // Trigger email alert on folder access
                lastAccessTime = currentAccessTime;
            }
        }
    }

    // Method to get the last access time of the folder
    private static long getLastAccessTime(String folderPath) {
        try {
            Path folder = Paths.get(folderPath);
            BasicFileAttributes attrs = Files.readAttributes(folder, BasicFileAttributes.class);
            return attrs.lastAccessTime().toMillis(); // Returns the last access time in milliseconds
        } catch (IOException e) {
            logger.severe("Error retrieving folder attributes: " + e.getMessage());
            return -1;
        }
    }
}

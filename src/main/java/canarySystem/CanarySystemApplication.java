package canarySystem;

import alertSystem.EmailAlert;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

@SpringBootApplication
@RestController
public class CanarySystemApplication {

    private static final String CANARY_FOLDER_PATH = "C:\\Manula\\Academics\\Master in Cyber Security\\Sem 4\\Project\\Codebase\\COMP6900_Canary\\src\\test\\java\\Important Folder";
    private static WatchService watchService;
    private static ExecutorService executorService = Executors.newSingleThreadExecutor();

    public static void main(String[] args) {
        SpringApplication.run(CanarySystemApplication.class, args);
    }


    // Method to fetch folder path from OutSystems API
    public static String getCanaryFolderPath() {
        String OUTSYSTEMS_API_URL = "https://personal-bbyqfyt5.outsystemscloud.com/WatchTower/rest/GetCanaryEndpoint/GetCanary";
        System.out.println(OUTSYSTEMS_API_URL);
        RestTemplate restTemplate = new RestTemplate();
        String folderPath = restTemplate.getForObject(OUTSYSTEMS_API_URL, String.class);
        System.out.println(folderPath);
        return folderPath;
    }
    // Endpoint to start folder monitoring
    @RequestMapping(value = "/startMonitoring", method = RequestMethod.POST)
    public String startMonitoring() {
        String folderPath = getCanaryFolderPath();  // Fetch folder path from OutSystems

        try {
            if (watchService == null) {
                watchService = FileSystems.getDefault().newWatchService();
                Path path = Paths.get(folderPath);  // Use dynamic folder path
                path.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_DELETE);

                // Start the monitoring process in a separate thread
                executorService.submit(() -> monitorFolder(folderPath));
                return "Monitoring started successfully!";
            } else {
                return "Monitoring is already running.";
            }
        } catch (IOException e) {
            e.printStackTrace();
            return "Error starting monitoring: " + e.getMessage();
        }
    }

    // Endpoint to stop folder monitoring
    @PostMapping("/stopMonitoring")
    public String stopMonitoring() {
        if (watchService != null) {
            try {
                watchService.close();
                watchService = null;
                return "Monitoring stopped successfully!";
            } catch (IOException e) {
                e.printStackTrace();
                return "Error stopping monitoring: " + e.getMessage();
            }
        }
        return "Monitoring is not running.";
    }

    // Method to monitor the folder and trigger alerts
    private void monitorFolder(String folderPath) {
        try {
            WatchKey key;
            // Map to store the last access time for each file
            Map<Path, FileTime> lastAccessTimes = new HashMap<>();

            // Initialize last access times for all files in the folder
            Files.walk(Paths.get(folderPath)).forEach(filePath -> {
                try {
                    lastAccessTimes.put(filePath, Files.readAttributes(filePath, BasicFileAttributes.class).lastAccessTime());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            });

            while ((key = watchService.take()) != null) {
                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();
                    Path fileName = (Path) event.context();
                    String fullFilePath = folderPath + "\\" + fileName.toString();

                    // Check for file modifications, creation, and deletion
                    if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {
                        System.out.println("File modified: " + fileName);
                        EmailAlert.sendEmailAlert(fullFilePath, "Modification");
                    } else if (kind == StandardWatchEventKinds.ENTRY_CREATE) {
                        System.out.println("New file created: " + fileName);
                        EmailAlert.sendEmailAlert(fullFilePath, "Creation");
                    } else if (kind == StandardWatchEventKinds.ENTRY_DELETE) {
                        System.out.println("File deleted: " + fileName);
                        EmailAlert.sendEmailAlert(fullFilePath, "Deletion");
                    }
                }
                key.reset();

                // Poll for file access (read) events by checking the last access time
                Files.walk(Paths.get(folderPath)).forEach(filePath -> {
                    try {
                        FileTime lastAccessTime = Files.readAttributes(filePath, BasicFileAttributes.class).lastAccessTime();
                        // Check if the file was accessed (read)
                        if (!lastAccessTime.equals(lastAccessTimes.get(filePath))) {
                            System.out.println("File accessed: " + filePath);
                            EmailAlert.sendEmailAlert(filePath.toString(), "access");
                            lastAccessTimes.put(filePath, lastAccessTime); // Update last access time
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                });
            }
        } catch (InterruptedException | IOException e) {
            e.printStackTrace();
        }
    }

    @GetMapping("/getStatus")
    public String getStatus() {
        if (watchService != null) {
            return "Monitoring is running.";
        }
        return "Monitoring is not running.";
    }
}

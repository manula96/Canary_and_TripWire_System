package canarySystem;

import alertSystem.EmailAlert;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.*;
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

    // Endpoint to start folder monitoring
    @RequestMapping(value = "/startMonitoring", method = RequestMethod.POST)
    public String startMonitoring() {
        try {
            if (watchService == null) {
                watchService = FileSystems.getDefault().newWatchService();
                Path path = Paths.get(CANARY_FOLDER_PATH);
                path.register(watchService, StandardWatchEventKinds.ENTRY_MODIFY, StandardWatchEventKinds.ENTRY_CREATE, StandardWatchEventKinds.ENTRY_DELETE);

                // Start the monitoring process in a separate thread
                executorService.submit(() -> monitorFolder(CANARY_FOLDER_PATH));
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
            while ((key = watchService.take()) != null) {
                for (WatchEvent<?> event : key.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();
                    Path fileName = (Path) event.context();
                    String fullFilePath = folderPath + "\\" + fileName.toString();

                    if (kind == StandardWatchEventKinds.ENTRY_MODIFY) {
                        System.out.println("File modified: " + fileName);
                        EmailAlert.sendEmailAlert(fullFilePath, "modified");
                    } else if (kind == StandardWatchEventKinds.ENTRY_CREATE) {
                        System.out.println("New file created: " + fileName);
                        EmailAlert.sendEmailAlert(fullFilePath, "created");
                    } else if (kind == StandardWatchEventKinds.ENTRY_DELETE) {
                        System.out.println("File deleted: " + fileName);
                        EmailAlert.sendEmailAlert(fullFilePath, "deleted");
                    }
                }
                key.reset();
            }
        } catch (InterruptedException e) {
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

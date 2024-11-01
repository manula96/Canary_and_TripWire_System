# Watch Tower: Canary and Tripwire System

**Watch Tower** is a Canary-Based Code Integrity Monitoring System designed for fintech applications. This system utilizes canary files and tripwire mechanisms to detect unauthorized access or modification within codebases. The project also integrates an email alert system to notify administrators of suspicious activities in real time.

## Project Structure

```plaintext
WatchTower
├── src
│   ├── main
│   │   └── java
│   │       ├── alertSystem
│   │       │   └── EmailAlert.java           # Handles email notifications for alerts
│   │       ├── canarySystem
│   │       │   ├── CanarySystem.java         # Core of the canary file monitoring logic
│   │       │   └── CanarySystemApplication.java # Main entry point for running the canary system
│   │       └── tripWireSystem
│   │           └── TripwireSystem.java       # Implements the tripwire monitoring system
│   └── test                                  # Test directory for unit and integration tests
├── target                                    # Compiled classes and build files
│   ├── classes
│   ├── generated-sources
│   └── maven-status
├── WatchTower.docx                           # Project documentation
├── WatchTower Framework 2_0.pdf              # Framework document detailing system architecture
├── StchTower.docx                            # Additional documentation (possibly a typo, check spelling)
└── pom.xml                                   # Maven build configuration file


Key Components

    alertSystem: Contains the EmailAlert module responsible for sending notifications when suspicious activities are detected by the canary or tripwire systems.

    canarySystem: This module includes CanarySystem and CanarySystemApplication, responsible for setting up and monitoring canary files to detect unauthorized access or modifications in critical areas of the codebase.

    tripWireSystem: The TripwireSystem module uses tripwire techniques to monitor for unexpected changes in specified directories or files.

package alertSystem;

import com.sun.mail.smtp.SMTPTransport;
import javax.mail.*;
import javax.mail.internet.*;
import java.util.Properties;

public class EmailAlert {

    private static final String ACCESS_TOKEN = "";
    private static final String EMAIL_FROM = "canaryalert119@gmail.com";  // Replace with your Gmail address
    private static final String EMAIL_TO = "ai.expert21815@gmail.com";  // The recipient's email address
    private static final String SMTP_SERVER = "smtp.gmail.com";
    private static final int SMTP_PORT = 587;

    public static void sendEmailAlert() {
        Properties props = new Properties();
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.host", SMTP_SERVER);
        props.put("mail.smtp.port", String.valueOf(SMTP_PORT));
        props.put("mail.smtp.ssl.trust", SMTP_SERVER);

        // Get a mail session
        Session session = Session.getInstance(props);
        session.setDebug(true);  // Enable debugging to see email sending process

        try {
            // Create a new email message
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(EMAIL_FROM));
            message.setRecipient(Message.RecipientType.TO, new InternetAddress(EMAIL_TO));
            message.setSubject("ALERT: File Modification Detected!");
            message.setText("A critical file was accessed or modified. Immediate attention required.");

            // Use SMTPTransport to send the message with OAuth2 authentication
            SMTPTransport transport = (SMTPTransport) session.getTransport("smtp");

            // Connect to the SMTP server (without specifying password)
            transport.connect(SMTP_SERVER, SMTP_PORT, EMAIL_FROM, null);

            // Issue the XOAUTH2 authentication command with the access token
            String oauth2Token = generateOAuth2Token(EMAIL_FROM, ACCESS_TOKEN);
            transport.issueCommand("AUTH XOAUTH2 " + oauth2Token, 235);  // 235 indicates successful authentication

            // Send the message
            transport.sendMessage(message, message.getAllRecipients());
            System.out.println("Email sent successfully.");

            transport.close();
        } catch (MessagingException e) {
            e.printStackTrace();
        }
    }

    // Method to generate the OAuth2 token for Gmail's XOAUTH2 authentication
    private static String generateOAuth2Token(String email, String accessToken) {
        return "user=" + email + "\1auth=Bearer " + accessToken + "\1\1";
    }
}

package ie.atu.taskmanagementregistration.Authentication;

import ie.atu.taskmanagementregistration.Config.JwtConfig;
import ie.atu.taskmanagementregistration.User.LoginUser;
import ie.atu.taskmanagementregistration.User.Notification;
import ie.atu.taskmanagementregistration.User.User;
import ie.atu.taskmanagementregistration.User.UserDB;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Optional;

@Service
public class AuthService {

    private final UserDB userDB;
    private final BCryptPasswordEncoder passEncoder;
    private final JwtConfig jwt;
    private final RabbitTemplate rabbitTemplate;

    public AuthService(UserDB userDB, BCryptPasswordEncoder passEncoder, JwtConfig jwt, RabbitTemplate rabbitTemplate) {
        this.userDB = userDB;
        this.passEncoder = passEncoder;
        this.jwt = jwt;
        this.rabbitTemplate = rabbitTemplate;
    }

    public ResponseEntity<String> register(User user) {
        Optional<User> existingUserOptional = userDB.findByEmail(user.getEmail());
        if (existingUserOptional.isPresent()) {
            return ResponseEntity.status(401).body("User already exists");
        } else {
            userDB.save(user);
            return ResponseEntity.ok("Thank you for joining us " + user.getFirstName());
        }
    }

    public ResponseEntity<String> login(LoginUser user) {
        Optional<User> existingUserOptional = userDB.findByEmail(user.getEmail());
        if (existingUserOptional.isPresent()) {
            User existingUser = existingUserOptional.get();
            if (!passEncoder.matches(user.getPassword(), existingUser.getPassword())) {
                return ResponseEntity.status(401).body("Password incorrect");
            }
            rabbitTemplate.convertAndSend("userNotificationQueue", user);
            return ResponseEntity.ok("Welcome " + existingUser.getFirstName() +
                    "\nToken: " + jwt.generateToken(existingUser.getEmail()));
        } else {
            return ResponseEntity.status(404).body("User not found");
        }
    }

    @RabbitListener(queues = "userNotificationQueue")
    public void receiveNotification(User user) {
        Notification notif = new Notification();
        notif.setEmail(user.getEmail());
        notif.setDateOfAction(LocalDate.now().format(DateTimeFormatter.ofPattern("dd-MM-yyyy")));
        System.out.println(notif);
    }
}

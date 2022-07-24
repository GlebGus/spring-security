package auth;

import com.google.common.collect.Lists;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static com.example.springsecurity.student.ApplicationUserRole.*;
@Repository("fake")
public class FakeApplicationUserDAOService implements ApplicationUserDAO{
    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDAOService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUser()
                .stream()
                .filter(applicationUser -> username.equals(applicationUser.getUsername()))
                .findFirst();
    }
    private List<ApplicationUser> getApplicationUser() {


        List<ApplicationUser> applicationUserList = Lists.newArrayList(new ApplicationUser(
                "annasmith",
                passwordEncoder.encode("password"),
                STUDENT.getGrantedAuthority(),
                true,
                true,
                true,
                true
                ),
                new ApplicationUser(
                "linda",
                passwordEncoder.encode("password123"),
                ADMIN.getGrantedAuthority(),
                true,
                true,
                true,
                true
        ),
        new ApplicationUser(
        "tom",
                passwordEncoder.encode("password123"),
                ADMINTRAINEE.getGrantedAuthority(),
                true,
                true,
                true,
                true
                )
        );

        return applicationUserList;
    }
}

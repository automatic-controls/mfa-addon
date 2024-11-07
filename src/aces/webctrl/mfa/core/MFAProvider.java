package aces.webctrl.mfa.core;
import com.controlj.green.addonsupport.web.auth.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
public class MFAProvider extends StandardWebOperatorProvider {
  public static String encodeURL(String param){
    return URLEncoder.encode(param,StandardCharsets.UTF_8).replace("+", "%20");
  }
  @Override public WebOperator login(HttpServletRequest req, HttpServletResponse res) throws ValidationException, IOException, ServletException {
    // TODO - Possible improvement - Create persistent cookie on client to bypass MFA for 1 day after one successful MFA authorization
    //        need to store hashmap of usernames to cookie ID on serverside, so that we can verify the cookie
    //        it would be preferable to save this hashmap to the config file to persist it across WebCTRL reboots
    String user = req.getParameter("name");
    String mode = req.getParameter("mode");
    if (user==null || "resetpw".equals(mode)){
      return super.login(req, res);
    }
    user = user.toLowerCase();
    String pass = req.getParameter("pass");
    if (pass==null) {
      pass = this.getChangePass(req);
    }
    final String token = req.getParameter("mfa_token");
    final String code = req.getParameter("mfa_code");
    if (token!=null && code!=null){
      try{
        final String otp = Config.getOTP(user);
        if ((otp!=null && Initializer.checkOTPCode(user, otp, code, token)) || Initializer.checkCode(user, Integer.parseInt(code), token, true)){
          return this.getBuiltinOperator(user);
        }else{
          res.sendRedirect(Initializer.getPrefix()+"error_page.jsp?m1="+encodeURL("An MFA error has occurred.")+"&m2="+encodeURL("The provided security code is incorrect."));
          return null;
        }
      }catch(NumberFormatException e){
        res.sendRedirect(Initializer.getPrefix()+"error_page.jsp?m1="+encodeURL("An MFA error has occurred.")+"&m2="+encodeURL("Could not parse one-time security code."));
        return null;
      }catch(URISyntaxException e){
        res.sendRedirect(Initializer.getPrefix()+"error_page.jsp?m1="+encodeURL("An MFA error has occurred.")+"&m2="+encodeURL("Could not parse TOTP URI."));
        return null;
      }
    }
    final String email = Config.getEmail(user);
    final boolean otp = Config.containsOTPFor(user);
    final char[] password = pass==null?new char[]{}:Utility.obfuscate(pass.toCharArray());
    pass = null;
    final String host = "web browser at "+req.getRemoteAddr();
    if (email==null && !otp && Config.enforceMFA && !Config.isWhitelisted(user)){
      super.validate(user, password, host);
      final EmailToken et = Initializer.generateEmailToken(user);
      res.sendRedirect(Initializer.getPrefix()+"ConfigureMFA?mfa_user="+encodeURL(user)+"&mfa_token="+encodeURL(et.getToken()));
      return null;
    }
    if (email==null && !otp){
      return super.login(req, res);
    }
    super.validate(user, password, host);
    final SecurityCode st = Initializer.generateCode(user);
    if (otp){
      res.sendRedirect(Initializer.getPrefix()+"QueryMFA?mfa_user="+encodeURL(user)+"&mfa_token="+encodeURL(st.getToken()));
      return null;
    }else{
      if (Config.sendEmail(email, st, 0L) || Config.sendEmail(email, st, 1500L)){
        res.sendRedirect(Initializer.getPrefix()+"QueryMFA?mfa_user="+encodeURL(user)+"&mfa_token="+encodeURL(st.getToken()));
        return null;
      }else if (!Config.isWhitelisted(user) && (!Config.bypassOnEmailFailure || Config.testEmailServer(false))){
        res.sendRedirect(Initializer.getPrefix()+"error_page.jsp?m1="+encodeURL("Failed to send MFA email.")+"&m2="+encodeURL("Please try again later."));
        return null;
      }else{
        return super.login(req, res);
      }
    }
  }
  public String getChangePass(HttpServletRequest req) {
    HttpSession session = req.getSession(false);
    if (session!=null){
      String changepass = (String)session.getAttribute("changepass");
      if (changepass!=null){
        session.setAttribute("changepass", null);
        return changepass;
      }
    }
    return null;
  }
  @Override public WebOperator validate(final String username, char[] password, String host) throws ValidationException {
    final String user = username.toLowerCase();
    if (host.startsWith("web browser at ") || Config.allowServiceLogins || !Config.enforceMFA && !Config.containsEmailFor(user) || Config.isWhitelisted(user)){
      return super.validate(username, password, host);
    }else{
      throw new ValidationException("Service logins are disabled because MFA is not supported.");
    }
  }
}
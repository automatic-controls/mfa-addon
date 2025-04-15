package aces.webctrl.mfa.core;
import aces.webctrl.mfa.web.RestAPI;
import com.controlj.green.addonsupport.web.auth.*;
import com.controlj.green.common.policy.PolicyUtils;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;
import java.net.*;
import java.util.regex.*;
import java.nio.charset.StandardCharsets;
public class MFAProvider extends StandardWebOperatorProvider {
  public static String encodeURL(String param){
    return URLEncoder.encode(param,StandardCharsets.UTF_8).replace("+", "%20");
  }
  @Override public WebOperator login(HttpServletRequest req, HttpServletResponse res) throws ValidationException, IOException, ServletException {
    String user = normalizeNewlines(req.getParameter("name"));
    String pass = normalizeNewlines(req.getParameter("pass"));
    // Uncomment the "resetpw" bit to allow ALC their password reset backdoor.
    if (user==null/* || "resetpw".equals(normalizeNewlines(req.getParameter("mode")))*/){
      return super.login(req, res);
    }
    if (pass==null){
      try{
        pass = getChangePass(req);
      }catch(Exception e){}
    }
    final char[] password = pass==null?new char[]{}:Utility.obfuscate(pass.toCharArray());
    if (!HelperAPI.validateUser(user, pass==null?null:new String(password))){
      PolicyUtils.delayFailedAttempt();
      throw new InvalidCredentialsException();
    }
    pass = null;
    user = user.toLowerCase();
    final String token = req.getParameter("mfa_token");
    final String code = req.getParameter("mfa_code");
    final Boolean apiNull = Config.isControlledByAPI(user,null);
    final boolean teapot = apiNull==null;
    final boolean api = teapot || apiNull;
    final String ip = Utility.getRemoteAddr(req);
    if (token!=null && code!=null){
      try{
        final String otp = api?null:Config.getOTP(user);
        if ((api || !Config.isRateLimited(user)) && ((api || otp!=null) && Initializer.checkOTPCode(user, otp, code, token, ip, true) || !api && Initializer.checkCode(user, Integer.parseInt(code), token, true))){
          if (api){
            Config.removeFromAPICache(user, code, ip);
          }else{
            Config.insertCookie(user, ip);
          }
          return this.getBuiltinOperator(user);
        }else{
          PolicyUtils.delayFailedAttempt();
          res.sendRedirect(Initializer.getPrefix()+"error_page.jsp?m1="+encodeURL("An MFA error has occurred.")+"&m2="+encodeURL("The provided security code is incorrect or the login rate limit has been exceeded."));
          return null;
        }
      }catch(NumberFormatException e){
        PolicyUtils.delayFailedAttempt();
        res.sendRedirect(Initializer.getPrefix()+"error_page.jsp?m1="+encodeURL("An MFA error has occurred.")+"&m2="+encodeURL("Could not parse one-time security code."));
        return null;
      }catch(URISyntaxException e){
        PolicyUtils.delayFailedAttempt();
        res.sendRedirect(Initializer.getPrefix()+"error_page.jsp?m1="+encodeURL("An MFA error has occurred.")+"&m2="+encodeURL("Could not parse TOTP URI."));
        return null;
      }
    }
    final String email = Config.emailEnabled && !api?Config.getEmail(user):null;
    final boolean otp = Config.containsOTPFor(user) && !api;
    final String host = "web browser at "+ip;
    if (email==null && !otp && !api){
      if (Config.enforceMFA && !Config.isWhitelisted(user)){
        super.validate(user, password, host);
        final EmailToken et = Initializer.generateEmailToken(user);
        res.sendRedirect(Initializer.getPrefix()+"ConfigureMFA?mfa_user="+encodeURL(user)+"&mfa_token="+encodeURL(et.getToken()));
        return null;
      }else{
        return super.login(req, res);
      }
    }
    if (api && !teapot && !Config.checkCookieAPI(user, ip) || !api && !Config.checkCookie(user, ip)){
      if (!api && RestAPI.LOGGING){
        Initializer.log(user+" bypassed MFA from "+ip+".");
      }
      return super.login(req, res);
    }
    super.validate(user, password, host);
    if (teapot){
      res.sendRedirect(Initializer.getPrefix()+"error_page.jsp?m1="+encodeURL("Your account requires MFA.")+"&m2="+encodeURL("Please login to "+Config.getServerURL()+" to configure an authenticator app."));
      return null;
    }
    final SecurityCode st = Initializer.generateCode(user);
    if (otp || api){
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
  @Override public WebOperator validate(final String username, char[] password, String host) throws ValidationException {
    final String user = username.toLowerCase();
    if (host.startsWith("web browser at ") || Config.allowServiceLogins || !Config.enforceMFA && !(Config.emailEnabled && Config.containsEmailFor(user) || Config.containsOTPFor(user) || Config.isControlledByAPI(user,true)) || Config.isWhitelisted(user)){
      return super.validate(username, password, host);
    }else{
      throw new ValidationException("Service logins are disabled because MFA is not supported.");
    }
  }
  private static String getChangePass(HttpServletRequest req) {
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
  private final static Pattern normalizer = Pattern.compile("[\\r\\n]++");
  private static String normalizeNewlines(String s){
    return s==null?null:normalizer.matcher(s).replaceAll("\n");
  }
}
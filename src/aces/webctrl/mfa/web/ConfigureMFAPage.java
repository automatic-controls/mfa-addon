package aces.webctrl.mfa.web;
import aces.webctrl.mfa.core.*;
import javax.servlet.http.*;
import java.io.*;
public class ConfigureMFAPage extends ServletBase {
  @Override public boolean checkRole(final HttpServletRequest req, final HttpServletResponse res) throws IOException {
    boolean ret = !req.isUserInRole("login");
    if (!ret){
      res.sendError(403, "You cannot access this page while logged in.");
    }
    return ret;
  }
  @Override public void exec(final HttpServletRequest req, final HttpServletResponse res) throws Throwable {
    String user = req.getParameter("mfa_user");
    final String token = req.getParameter("mfa_token");
    final String action = req.getParameter("action");
    if (user==null || token==null || !Initializer.checkEmailToken(user=user.toLowerCase(), token, "save".equals(action))){
      if (action==null){
        res.sendRedirect("/");
      }else{
        res.setStatus(403);
      }
      return;
    }
    if (Config.isControlledByAPI(user,true)){
      res.sendError(403, "Please change your MFA settings from "+Config.getServerURL());
      return;
    }
    String email = Config.emailEnabled?Config.getEmail(user):null;
    if (email!=null){
      res.sendError(400, "An MFA email has already been configured for this user.");
      return;
    }
    if (action==null){
      res.setContentType("text/html");
      res.getWriter().print(getHTML(req)
        .replace("__USER__", Utility.escapeJS(user))
        .replace("__TOKEN__", Utility.escapeJS(token))
        .replace("__EMAIL_ENABLED__", String.valueOf(Config.emailEnabled))
      );
    }else if (action.equals("otp")){
      final String otp = Utility.createOTP(user);
      Config.setOTP(user,otp);
      Config.saveData();
      res.setContentType("text/plain");
      res.getWriter().print(otp);
      Initializer.log("Configured authenticator for "+user+".");
    //}else if (action.equals("testOTP")){
    //  final String otp = req.getParameter("otp");
    //  final String code = req.getParameter("code");
    //  if (otp==null || code==null){
    //    res.setStatus(400);
    //    return;
    //  }
    //  boolean b;
    //  try{
    //    b = Utility.checkCode(otp, code);
    //  }catch (java.net.URISyntaxException e){
    //    res.setStatus(400);
    //    return;
    //  }
    //  res.setContentType("text/plain");
    //  res.getWriter().print(b?"1":"0");
    }else if (action.equals("save") && Config.emailEnabled){
      email = req.getParameter("mfa_email");
      if (email==null){
        res.setStatus(400);
        return;
      }
      Config.setEmail(user,email);
      Config.saveData();
    }else{
      res.sendError(400, "Invalid action parameter.");
    }
  }
}
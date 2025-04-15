package aces.webctrl.mfa.web;
import aces.webctrl.mfa.core.*;
import javax.servlet.http.*;
import java.io.*;
public class ChangeEmailPage extends ServletBase {
  @Override public boolean checkRole(final HttpServletRequest req, final HttpServletResponse res) throws IOException {
    boolean ret = req.isUserInRole("login");
    if (!ret){
      res.sendError(403, "You must be logged in to access this page.");
    }
    return ret;
  }
  @Override public void exec(final HttpServletRequest req, final HttpServletResponse res) throws Throwable {
    final String user = getUsername(req);
    if (Config.isControlledByAPI(user,true)){
      res.sendError(403, "Please change your MFA settings from "+Config.getServerURL());
      return;
    }
    final String action = req.getParameter("action");
    if (action==null){
      final String email = Config.emailEnabled?Config.getEmail(user):null;
      res.setContentType("text/html");
      res.getWriter().print(getHTML(req)
        .replace("__EMAIL__", Utility.escapeJS(email))
        .replace("__EMAIL_ENABLED__", String.valueOf(Config.emailEnabled))
      );
    }else if (action.equals("save") && Config.emailEnabled){
      final String email = req.getParameter("mfa_email");
      if (email==null){
        res.setStatus(400);
        return;
      }
      Config.setEmail(user,email);
      Config.saveData();
    }else if (action.equals("otp")){
      final String otp = Utility.createOTP(user);
      Config.setOTP(user,otp);
      Config.saveData();
      res.setContentType("text/plain");
      res.getWriter().print(otp);
    }else{
      res.sendError(400, "Invalid action parameter.");
    }
  }
}
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
    final String user = req.getParameter("mfa_user");
    final String token = req.getParameter("mfa_token");
    final String action = req.getParameter("action");
    if (user==null || token==null || !Initializer.checkEmailToken(user, token, "save".equals("action"))){
      if (action==null){
        res.sendRedirect("/");
      }else{
        res.setStatus(403);
      }
      return;
    }
    String email = Config.getEmail(user);
    if (email!=null){
      res.sendError(400, "An MFA email has already been configured for this user.");
      return;
    }
    if (action==null){
      res.setContentType("text/html");
      res.getWriter().print(getHTML(req)
        .replace("__USER__", Utility.escapeJS(user))
        .replace("__TOKEN__", Utility.escapeJS(token))
      );
    }else if (action.equals("save")){
      email = req.getParameter("mfa_email");
      if (email==null){
        res.setStatus(400);
        return;
      }
      Config.setMapping(user,email);
      Config.saveData();
    }else{
      res.sendError(400, "Invalid action parameter.");
    }
  }
}
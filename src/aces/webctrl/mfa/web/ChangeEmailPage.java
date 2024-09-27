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
    final String action = req.getParameter("action");
    if (action==null){
      final String email = Config.getEmail(user);
      res.setContentType("text/html");
      res.getWriter().print(getHTML(req)
        .replace("__EMAIL__", Utility.escapeJS(email))
      );
    }else if (action.equals("save")){
      final String email = req.getParameter("mfa_email");
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
package aces.webctrl.mfa.web;
import aces.webctrl.mfa.core.*;
import javax.servlet.http.*;
import java.io.*;
public class QueryMFAPage extends ServletBase {
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
    SecurityCode sc;
    if (user==null || token==null || (sc=Initializer.getCode(user))==null || !sc.getToken().equals(token)){
      if (action==null){
        res.sendRedirect("/");
      }else{
        res.setStatus(403);
      }
      return;
    }
    String email = Config.getEmail(user);
    String otp = Config.getOTP(user);
    if (email==null && otp==null){
      if (action==null){
        res.sendRedirect("/");
      }else{
        res.setStatus(403);
      }
      return;
    }
    if (action==null){
      res.setContentType("text/html");
      res.getWriter().print(getHTML(req)
        .replace("__USER__", Utility.escapeJS(user))
        .replace("__TOKEN__", Utility.escapeJS(token))
        .replace("__EMAIL__", email==null?"":Utility.escapeJS(email))
        .replace("__EXPIRY__", String.valueOf(sc.expiry))
        .replace("__OTP__", String.valueOf(otp!=null))
      );
    }else if (action.equals("checkCode")){
      final String code = req.getParameter("mfa_code");
      if (code==null){
        res.setStatus(400);
        return;
      }
      if (otp!=null && Utility.checkCode(otp, code)){
        res.setContentType("text/plain");
        res.getWriter().print("1");
        return;
      }
      if (email==null){
        Initializer.checkCode(user, sc.code+1, token, false);
        res.setContentType("text/plain");
        res.getWriter().print("0");
        return;
      }
      int c;
      try{
        c = Integer.parseInt(code);
      }catch(NumberFormatException e){
        res.setStatus(400);
        return;
      }
      res.setContentType("text/plain");
      res.getWriter().print(Initializer.checkCode(user, c, token, false)?"1":"0");
    }else if (action.equals("resendCode")){
      final SecurityCode st = Initializer.generateCode(user);
      if (Config.sendEmail(email, st, 0L) || Config.sendEmail(email, st, 1500L)){
        res.setContentType("text/plain");
        res.getWriter().print(st.getToken());
      }else{
        res.setStatus(500);
      }
    }else{
      res.sendError(400, "Invalid action parameter.");
    }
  }
}
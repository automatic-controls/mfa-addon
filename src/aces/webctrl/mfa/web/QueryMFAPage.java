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
    String user = req.getParameter("mfa_user");
    final String token = req.getParameter("mfa_token");
    final String action = req.getParameter("action");
    SecurityCode sc;
    if (user==null || token==null || (sc=Initializer.getCode(user=user.toLowerCase()))==null || !sc.getToken().equals(token)){
      if (action==null){
        res.sendRedirect("/");
      }else{
        res.setStatus(403);
      }
      return;
    }
    final boolean api = Config.isControlledByAPI(user,true);
    String email = Config.emailEnabled && !api?Config.getEmail(user):null;
    String otp = api?null:Config.getOTP(user);
    if (!api && email==null && otp==null){
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
        .replace("__OTP__", String.valueOf(api || otp!=null))
      );
    }else if (action.equals("checkCode")){
      final String code = req.getParameter("mfa_code");
      if (code==null){
        res.setStatus(400);
        return;
      }
      if (api){
        res.setContentType("text/plain");
        res.getWriter().print(Config.submitToAPI(user, code, Utility.getRemoteAddr(req), true)?"1":"0");
        return;
      }
      if (Config.isRateLimited(user)){
        res.setContentType("text/plain");
        res.getWriter().print("0");
        if (RestAPI.LOGGING){ Initializer.log(user+" submitted a security code from "+Utility.getRemoteAddr(req)+" and was unsuccessful."); }
        return;
      }
      if (otp!=null && Utility.checkCode(otp, code)){
        res.setContentType("text/plain");
        res.getWriter().print("1");
        if (RestAPI.LOGGING){ Initializer.log(user+" submitted a security code from "+Utility.getRemoteAddr(req)+" and was successful."); }
        return;
      }
      if (email==null){
        Initializer.checkCode(user, sc.code+1, token, false);
        res.setContentType("text/plain");
        res.getWriter().print("0");
        if (RestAPI.LOGGING){ Initializer.log(user+" submitted a security code from "+Utility.getRemoteAddr(req)+" and was unsuccessful."); }
        return;
      }
      int c;
      try{
        c = Integer.parseInt(code);
      }catch(NumberFormatException e){
        res.setStatus(400);
        return;
      }
      final boolean ret = Initializer.checkCode(user, c, token, false);
      res.setContentType("text/plain");
      res.getWriter().print(ret?"1":"0");
      if (RestAPI.LOGGING){ Initializer.log(user+" submitted a security code from "+Utility.getRemoteAddr(req)+" and was "+(ret?"":"un")+"successful."); }
    }else if (action.equals("resendCode") && email!=null){
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
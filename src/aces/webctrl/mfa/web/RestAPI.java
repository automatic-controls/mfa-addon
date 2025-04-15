package aces.webctrl.mfa.web;
import aces.webctrl.mfa.core.*;
import javax.servlet.http.*;
public class RestAPI extends ServletBase {
  public final static boolean LOGGING = true;
  public boolean checkRole(final HttpServletRequest req, final HttpServletResponse res){
    return true;
  }
  @Override public void exec(final HttpServletRequest req, final HttpServletResponse res) throws Throwable {
    if (!Config.apiEnabled){
      res.setStatus(404);
      return;
    }else{
      final String apiKey = Config.apiKey;
      if (apiKey==null || apiKey.isBlank() || !apiKey.equalsIgnoreCase(req.getParameter("key"))){
        res.setStatus(403);
        return;
      }
    }
    String query = req.getParameter("query");
    String user = req.getParameter("user");
    String src = req.getParameter("src");
    if (query==null || user==null){
      res.setStatus(400);
      return;
    }
    if (src==null){
      src = Utility.getRemoteAddr(req);
    }
    query = query.toLowerCase();
    user = user.toLowerCase();
    final Boolean apiNull = Config.isControlledByAPI(user,null);
    final boolean teapot = apiNull==null;
    final boolean api = teapot || apiNull;
    switch (query){
      case "submit":{ // Submit a security code
        String ip = req.getParameter("ip");
        final String code = req.getParameter("code");
        if (code==null || ip==null){
          res.setStatus(400);
          return;
        }
        ip = ip.toLowerCase();
        final String otp = api?null:Config.getOTP(user);
        boolean limited = false;
        if ((api || otp!=null && !(limited=Config.isRateLimited(user))) && Initializer.checkOTPCode(user, otp, code, null, ip, false)){
          if (!api){
            Config.insertCookie(user, ip);
          }
          res.setStatus(200); // The provided security code is correct.
          if (LOGGING){ Initializer.log("RESTAPI - "+src+" - "+user+" submitted a security code from "+ip+" and was successful."); }
        }else{
          if (!api && !limited){
            Config.addFailedAttempt(user);
          }
          res.setStatus(404); // The provided security code is incorrect or the login rate limit has been exceeded.
          if (LOGGING){ Initializer.log("RESTAPI - "+src+" - "+user+" submitted a security code from "+ip+" and was unsuccessful."); }
        }
        break;
      }
      case "bypass":{ // Whether the specified user can bypass MFA
        String ip = req.getParameter("ip");
        if (ip==null){
          res.setStatus(400);
          return;
        }
        ip = ip.toLowerCase();
        if (api && !Config.checkCookieAPI(user, ip) || !api && !Config.checkCookie(user, ip)){
          res.setStatus(200); // yes, the user can bypass MFA
          if (LOGGING){ Initializer.log("RESTAPI - "+src+" - "+user+" bypassed MFA from "+ip+"."); }
        }else{
          res.setStatus(404); // no, the user cannot bypass MFA
          if (LOGGING){ Initializer.log("RESTAPI - "+src+" - "+user+" cannot bypass MFA from "+ip+"."); }
        }
        break;
      }
      case "control":{ // Whether the specified user is controlled by this server
        if (!teapot && (api || Config.containsOTPFor(user))){
          res.setStatus(200); // yes, the user is controlled by this server
          if (LOGGING){ Initializer.log("RESTAPI - "+src+" - "+user+" is controlled by this server."); }
        }else if (teapot || Config.enforceMFA && !Config.isWhitelisted(user) && HelperAPI.validateUser(user,null)){
          res.setStatus(418); // this user should be controlled by this server, but has not configured MFA yet
          if (LOGGING){ Initializer.log("RESTAPI - "+src+" - "+user+" has been prompted to configure MFA."); }
        }else{
          res.setStatus(404); // no, the user is not controlled by this server
          if (LOGGING){ Initializer.log("RESTAPI - "+src+" - "+user+" is not controlled by this server."); }
        }
        break;
      }
      default:{
        res.setStatus(400);
        break;
      }
    }
  }
}

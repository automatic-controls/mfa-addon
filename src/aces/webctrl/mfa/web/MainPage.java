package aces.webctrl.mfa.web;
import aces.webctrl.mfa.core.*;
import javax.servlet.http.*;
import java.util.*;
public class MainPage extends ServletBase {
  @Override public void exec(final HttpServletRequest req, final HttpServletResponse res) throws Throwable {
    final String action = req.getParameter("action");
    if (action==null){
      res.setContentType("text/html");
      res.getWriter().print(getHTML(req));
    }else if (action.equals("deleteOTP")){
      final String user = req.getParameter("user");
      if (user==null){
        res.setStatus(400);
        return;
      }
      Config.setOTP(user,null);
      Config.saveData();
    }else if (action.equals("save")){
      final String enforceMFA = req.getParameter("enforceMFA");
      final String allowServiceLogins = req.getParameter("allowServiceLogins");
      final String bypassOnEmailFailure = req.getParameter("bypassOnEmailFailure");
      final String mappings = req.getParameter("mappings");
      final String whitelist = req.getParameter("whitelist");
      if (enforceMFA==null || allowServiceLogins==null || bypassOnEmailFailure==null || mappings==null || whitelist==null){
        res.setStatus(400);
        return;
      }
      boolean _enforceMFA;
      boolean _allowServiceLogins;
      boolean _bypassOnEmailFailure;
      ArrayList<String> _mappings;
      ArrayList<String> _whitelist;
      try{
        _enforceMFA = Boolean.parseBoolean(enforceMFA);
        _allowServiceLogins = Boolean.parseBoolean(allowServiceLogins);
        _bypassOnEmailFailure = Boolean.parseBoolean(bypassOnEmailFailure);
        _mappings = Utility.decodeList(mappings);
        _whitelist = Utility.decodeList(whitelist);
      }catch(Throwable t){
        Initializer.log(t);
        res.setStatus(400);
        return;
      }
      int s = _mappings.size();
      if ((s&1)==1){
        res.setStatus(400);
        return;
      }
      s>>=1;
      final HashMap<String,String> map = new HashMap<>((int)Math.ceil(s/0.75));
      String k,v;
      for (int i=0,j=0;i<s;++i,++j){
        k = _mappings.get(j);
        v = _mappings.get(++j);
        map.put(k,v);
      }
      Config.enforceMFA = _enforceMFA;
      Config.allowServiceLogins = _allowServiceLogins;
      Config.bypassOnEmailFailure = _bypassOnEmailFailure;
      Config.setWhitelist(_whitelist);
      Config.setEmails(map);
      Config.saveData();
    }else if (action.equals("load")){
      final StringBuilder sb = new StringBuilder(1024);
      sb.append(Utility.format("{\"enforceMFA\":$0,\"allowServiceLogins\":$1,\"bypassOnEmailFailure\":$2,", Config.enforceMFA, Config.allowServiceLogins, Config.bypassOnEmailFailure));
      sb.append("\"mappings\":");
      Config.printEmails(sb);
      sb.append(",\"whitelist\":");
      Config.printWhitelist(sb);
      sb.append(",\"otps\":");
      Config.printOTPs(sb);
      sb.append('}');
      res.setContentType("application/json");
      res.getWriter().print(sb.toString());
    }else{
      res.sendError(400, "Invalid action parameter.");
    }
  }
}
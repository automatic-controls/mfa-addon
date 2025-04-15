package aces.webctrl.mfa.web;
import aces.webctrl.mfa.core.*;
import javax.servlet.http.*;
import javax.servlet.annotation.MultipartConfig;

import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.nio.file.StandardOpenOption;
import java.util.*;
@MultipartConfig
public class MainPage extends ServletBase {
  @Override public void exec(final HttpServletRequest req, final HttpServletResponse res) throws Throwable {
    final String action = req.getParameter("action");
    if (action==null){
      res.setContentType("text/html");
      res.getWriter().print(getHTML(req));
      return;
    }
    switch (action.toLowerCase()){
      case "deleteotp":{
        String user = req.getParameter("user");
        if (user==null){
          res.setStatus(400);
          return;
        }
        user = user.toLowerCase();
        Config.setOTP(user,null);
        Config.saveData();
        break;
      }
      case "save":{
        final String enforceMFA = req.getParameter("enforceMFA");
        final String allowServiceLogins = req.getParameter("allowServiceLogins");
        final String bypassOnEmailFailure = req.getParameter("bypassOnEmailFailure");
        final String emailEnabled = req.getParameter("emailEnabled");
        final String apiEnabled = req.getParameter("apiEnabled");
        final String trustProxyHeaders = req.getParameter("trustProxyHeaders");
        final String cookiesEnabled = req.getParameter("cookiesEnabled");
        final String mappings = req.getParameter("mappings");
        final String whitelist = req.getParameter("whitelist");
        if (enforceMFA==null || allowServiceLogins==null || bypassOnEmailFailure==null || mappings==null || whitelist==null || emailEnabled==null || apiEnabled==null || trustProxyHeaders==null || cookiesEnabled==null){
          res.setStatus(400);
          return;
        }
        boolean _enforceMFA;
        boolean _allowServiceLogins;
        boolean _bypassOnEmailFailure;
        boolean _emailEnabled;
        boolean _apiEnabled;
        boolean _trustProxyHeaders;
        boolean _cookiesEnabled;
        ArrayList<String> _mappings;
        ArrayList<String> _whitelist;
        try{
          _enforceMFA = Boolean.parseBoolean(enforceMFA);
          _allowServiceLogins = Boolean.parseBoolean(allowServiceLogins);
          _bypassOnEmailFailure = Boolean.parseBoolean(bypassOnEmailFailure);
          _emailEnabled = Boolean.parseBoolean(emailEnabled);
          _apiEnabled = Boolean.parseBoolean(apiEnabled);
          _trustProxyHeaders = Boolean.parseBoolean(trustProxyHeaders);
          _cookiesEnabled = Boolean.parseBoolean(cookiesEnabled);
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
        Config.emailEnabled = _emailEnabled;
        Config.apiEnabled = _apiEnabled;
        Config.trustProxyHeaders = _trustProxyHeaders;
        Config.cookiesEnabled = _cookiesEnabled;
        Config.setWhitelist(_whitelist);
        Config.setEmails(map);
        Config.saveData();
        break;
      }
      case "load":{
        final StringBuilder sb = new StringBuilder(1024);
        sb.append(Utility.format(
          "{\"enforceMFA\":$0,\"allowServiceLogins\":$1,\"bypassOnEmailFailure\":$2,\"emailEnabled\":$3,\"apiEnabled\":$4,\"trustProxyHeaders\":$5,\"cookiesEnabled\":$6,",
          Config.enforceMFA,
          Config.allowServiceLogins,
          Config.bypassOnEmailFailure,
          Config.emailEnabled,
          Config.apiEnabled,
          Config.trustProxyHeaders,
          Config.cookiesEnabled
        ));
        sb.append("\"mappings\":");
        Config.printEmails(sb);
        sb.append(",\"whitelist\":");
        Config.printWhitelist(sb);
        sb.append(",\"otps\":");
        Config.printOTPs(sb);
        sb.append('}');
        res.setContentType("application/json");
        res.getWriter().print(sb.toString());
        break;
      }
      case "apikey":{
        final String key = Config.generateNewAPIKey();
        Config.saveData();
        res.setContentType("text/plain");
        res.getWriter().print(key);
        break;
      }
      case "deleteapi":{
        Config.deleteServerURL();
        res.setStatus(200);
        break;
      }
      case "uploadapi":{
        final Part filePart = req.getPart("file");
        if (filePart==null || filePart.getSize()>8388608){
          res.setStatus(400);
          return;
        }
        ByteBuffer buf = ByteBuffer.allocate(8192);
        boolean go = true;
        synchronized (Config.class){
          try(
            ReadableByteChannel in = Channels.newChannel(filePart.getInputStream());
            FileChannel out = FileChannel.open(Config.urlFile, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);        
          ){
            do {
              do {
                go = in.read(buf)!=-1;
              } while (go && buf.hasRemaining());
              buf.flip();
              while (buf.hasRemaining()){
                out.write(buf);
              }
              buf.clear();
            } while (go);
          }
        }
        Config.resetServerURL();
        Config.getServerURL();
        res.setStatus(200);
        break;
      }
      default:{
        res.sendError(400, "Invalid action parameter.");
      }
    }
  }
}
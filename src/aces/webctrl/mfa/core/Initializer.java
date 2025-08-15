package aces.webctrl.mfa.core;
import com.controlj.green.addonsupport.*;
import com.controlj.green.core.main.CoreProduct;
import com.controlj.green.common.LanguageManager;
import javax.servlet.*;
import java.nio.file.*;
import java.util.*;
import java.net.URISyntaxException;
// # TODO
// - Implement **Bypass MFA on Upstream Server Failure** option that is enabled by default
//   - Maybe implement cache so that only api users are blocked when the api server is inaccessible
/**
 * This class contains most of the life-cycle management logic for this add-on.
 */
public class Initializer implements ServletContextListener {
  /** Whether to automatically deploy this add-on as WebCTRL's authentication provider */
  private final static boolean AUTO_DEPLOY = true;
  /** Whether to log to stdout or to a log file unique to this add-on */
  private final static boolean LOG_TO_STDOUT = false;
  /** Contains basic information about this addon */
  public volatile static AddOnInfo info = null;
  /** The owner specified in the WebCTRL license file prefixed with &src= */
  public volatile static String licensedTo = "";
  /** The name of this addon */
  private volatile static String name;
  /** Prefix used for constructing relative URL paths */
  private volatile static String prefix;
  /** Path to the private directory for this addon */
  private volatile static Path root;
  /** Logger for this addon */
  private volatile static FileLogger logger;
  /** Whether to stop the primary thread */
  private volatile static boolean stop = false;
  /** Contains one-time security codes which expire 5 minutes after creation or after 3 failed attempts */
  private final static HashMap<String,SecurityCode> securityCodes = new HashMap<>(16);
  /** Contains tokens used to setup MFA for the first time */
  private final static HashMap<String,EmailToken> emailTokens = new HashMap<>(16);
  /**
   * Entry point of this add-on.
   */
  @Override public void contextInitialized(ServletContextEvent sce){
    info = AddOnInfo.getAddOnInfo();
    name = info.getName();
    prefix = '/'+name+'/';
    root = info.getPrivateDir().toPath();
    logger = info.getDateStampLogger();
    try{
      licensedTo = CoreProduct.getOwnerName(LanguageManager.getSystemLocale().toString()).trim();
      if (licensedTo.isEmpty()){
        licensedTo = "";
      }else{
        licensedTo = "&src="+MFAProvider.encodeURL(licensedTo);
      }
    }catch(Throwable t){}
    Config.init(root.resolve("params.dat"), root.resolve("url.dat"), root.resolve("cookies.dat"));
    if (AUTO_DEPLOY){
      HelperAPI.logoutAllForeign();
      HelperAPI.activateWebOperatorProvider(name);
    }
    deleteGhosts();
  }
  /**
   * Releases resources.
   */
  @Override public void contextDestroyed(ServletContextEvent sce){
    stop = true;
    if (AUTO_DEPLOY){
      HelperAPI.activateDefaultWebOperatorProvider();
    }
    Config.saveData();
  }
  public static void deleteGhosts(){
    final Map<String,String> map = HelperAPI.getLocalOperators();
    if (map!=null){
      Set<String> set = map.keySet();
      //HashSet<String> users = HashSet.newHashSet(set.size());
      HashSet<String> users = new HashSet<>((int)Math.ceil(set.size()/0.75));
      for (String s: set){
        users.add(s.toLowerCase());
      }
      if (Config.deleteUnused(users)){
        Config.saveData();
      }
    }
  }
  /**
   * Generate a new email token for the specified user.
   */
  public static EmailToken generateEmailToken(String username){
    username = username.toLowerCase();
    synchronized (emailTokens){
      if (emailTokens.size()>4096){
        clearExpiredTokens();
      }
      final EmailToken c = new EmailToken();
      emailTokens.put(username, c);
      return c;
    }
  }
  /**
   * Check whether the given email token is correct for the specified user.
   */
  public static boolean checkEmailToken(String username, String token, boolean removeOnSuccess){
    username = username.toLowerCase();
    synchronized (emailTokens){
      clearExpiredTokens();
      final EmailToken c = emailTokens.get(username);
      if (c==null){
        return false;
      }
      if (token.equals(c.getToken())){
        if (removeOnSuccess){
          emailTokens.remove(username);
        }
        return true;
      }else{
        return false;
      }
    }
  }
  /**
   * Clear all expired email tokens.
   */
  private static void clearExpiredTokens(){
    final long currentTime = System.currentTimeMillis();
    final Iterator<EmailToken> iter = emailTokens.values().iterator();
    EmailToken c;
    while (iter.hasNext()){
      c = iter.next();
      if (c.isExpired(currentTime)){
        iter.remove();
      }
    }
  }
  /**
   * Generate a new security code for the specified user.
   */
  public static SecurityCode generateCode(String username){
    username = username.toLowerCase();
    synchronized (securityCodes){
      if (securityCodes.size()>4096){
        clearExpiredCodes();
      }
      final SecurityCode c = new SecurityCode();
      securityCodes.put(username, c);
      return c;
    }
  }
  public static SecurityCode getCode(String username){
    synchronized (securityCodes){
      clearExpiredCodes();
      return securityCodes.get(username);
    }
  }
  /**
   * Check whether the given security code is correct for the specified user.
   */
  public static boolean checkCode(String username, int code, String token, boolean removeOnSuccess){
    username = username.toLowerCase();
    boolean ret = true;
    try{
      synchronized (securityCodes){
        clearExpiredCodes();
        final SecurityCode c = securityCodes.get(username);
        if (c==null || !token.equals(c.getToken())){
          return ret=false;
        }
        if (c.code==code && c.code!=0){
          if (removeOnSuccess){
            c.attempts = 0;
          }
          return ret=true;
        }else{
          --c.attempts;
          return ret=false;
        }
      }
    }finally{
      if (!ret){
        Config.addFailedAttempt(username);
      }
    }
  }
  /**
   * Check whether the given security code is correct for the specified user.
   */
  public static boolean checkOTPCode(String username, String otp, String code, String token, String ip, boolean cache) throws URISyntaxException {
    username = username.toLowerCase();
    if (token==null){
      if (otp!=null && Utility.checkCode(otp,code) || otp==null && Config.submitToAPI(username, code, ip, cache)){
        if (otp!=null && Config.codeAlreadySubmitted(username, code)){
          return false;
        }
        return true;
      }else{
        return false;
      }
    }else{
      synchronized (securityCodes){
        clearExpiredCodes();
        final SecurityCode c = securityCodes.get(username);
        if (c==null || !token.equals(c.getToken())){
          return false;
        }
        if (otp!=null && Utility.checkCode(otp,code) || otp==null && Config.submitToAPI(username, code, ip, cache)){
          if (otp!=null && Config.codeAlreadySubmitted(username, code)){
            return false;
          }
          c.attempts = 0;
          return true;
        }else{
          return false;
        }
      }
    }
  }
  /**
   * Clear all expired security codes.
   */
  private static void clearExpiredCodes(){
    final long currentTime = System.currentTimeMillis();
    final Iterator<SecurityCode> iter = securityCodes.values().iterator();
    SecurityCode c;
    while (iter.hasNext()){
      c = iter.next();
      if (c.isExpired(currentTime) || c.attempts==0){
        iter.remove();
      }
    }
  }
  /**
   * @return whether any active threads should be killed.
   */
  public static boolean isKilled(){
    return stop;
  }
  /**
   * @return the name of this application.
   */
  public static String getName(){
    return name;
  }
  /**
   * @return the prefix used for constructing relative URL paths.
   */
  public static String getPrefix(){
    return prefix;
  }
  /**
   * Logs a message.
   */
  public synchronized static void log(String str){
    if (LOG_TO_STDOUT){
      System.out.println(str);
    }else{
      logger.println(str);
    }
  }
  /**
   * Logs an error.
   */
  public synchronized static void log(Throwable t){
    if (LOG_TO_STDOUT){
      t.printStackTrace();
    }else{
      logger.println(t);
    }
  }
}
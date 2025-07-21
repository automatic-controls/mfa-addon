package aces.webctrl.mfa.core;
import com.controlj.green.core.email.*;
import javax.mail.*;
import java.net.*;
import java.net.http.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.locks.*;
import java.util.function.Predicate;
import java.util.regex.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.channels.*;
import java.lang.reflect.*;
public class Config {
  /** The path to the saved data file. */
  private static volatile Path mainFile;
  public static volatile Path urlFile;
  private static volatile Path cookieFile;
  private final static HashMap<String,String> usernameEmailMappings = new HashMap<>(32);
  private final static ReentrantReadWriteLock mapLock = new ReentrantReadWriteLock();
  private final static HashMap<String,String> usernameOTPMappings = new HashMap<>(32);
  private final static ReentrantReadWriteLock otpLock = new ReentrantReadWriteLock();
  private final static HashMap<String,IPCookie> cookieMappings = new HashMap<>(64);
  private final static ReentrantReadWriteLock cookieLock = new ReentrantReadWriteLock();
  private final static ConcurrentLinkedQueue<Attempt> attempts = new ConcurrentLinkedQueue<>();
  private final static ConcurrentHashMap<String,Long> userAPICache = new ConcurrentHashMap<String,Long>(32);
  private final static ConcurrentHashMap<String,Long> apiResponseCache = new ConcurrentHashMap<String,Long>(32);
  private final static ConcurrentHashMap<String,Long> submittedCodeCache = new ConcurrentHashMap<String,Long>(32);
  /**
   * When {@link #enforceMFA} is enabled, these users are exceptions where MFA is not necessarily enforced.
   * When the MFA email fails to send, these users can bypass MFA in all cases.
   */
  private final static HashSet<String> whitelist = new HashSet<>(16);
  private final static ReentrantReadWriteLock whitelistLock = new ReentrantReadWriteLock();
  /**
   * Specifies whether to enforce MFA for all users.
   * Users added to the {@link #whitelist} are exceptions.
   */
  public volatile static boolean enforceMFA = false;
  /**
   * Specifies whether to allow service logins like SOAP and Telnet for MFA-enabled users.
   * Note that service logins do not support MFA.
   * Users added to the {@link #whitelist} are exceptions when service logins are disabled.
   */
  public volatile static boolean allowServiceLogins = true;
  /**
   * If {@code true}, MFA can be bypassed when WebCTRL's email configuration is invalid.
   * If {@code false}, users with MFA enabled will be unable to login when WebCTRL's email server is down.
   */
  public volatile static boolean bypassOnEmailFailure = true;
  /**
   * Specifies whether a request should be accepted without MFA if the user has already used MFA within the last week from the same IP address.
   */
  public volatile static boolean cookiesEnabled = true;
  /**
   * Specifies whether emailed security codes are enabled.
   */
  public volatile static boolean emailEnabled = true;
  /**
   * Specifies whether the REST API is enabled.
   */
  public volatile static boolean apiEnabled = false;
  /**
   * Specifies whether to trust the Forwarded, X-Forwarded-For, and X-Real-IP headers when determining the user's IP address.
   */
  public volatile static boolean trustProxyHeaders = false;
  /**
   * Specifies the API key to accept with REST API requests.
   */
  public volatile static String apiKey = "";
  /**
   * Specifies the base URL of another server with the MFA add-on's REST API enabled.
   * If this is set, the MFA add-on will forward certain requests to this server.
   */
  private volatile static String serverURL = null;
  /**
   * Specifies the API key to use when forwarding requests to {@link #serverURL}.
   */
  private volatile static String serverAPIKey = null;
  /**
   * Specifies the next time to load the serverURL.
   */
  private volatile static long nextURLCheck = 0;
  /**
   * Sets the path to the saved data file and attempts to load any available data.
   */
  public static void init(Path mainFile, Path urlFile, Path cookieFile){
    Config.mainFile = mainFile;
    Config.urlFile = urlFile;
    Config.cookieFile = cookieFile;
    loadData();
  }
  public static boolean deleteUnused(Set<String> users){
    final Predicate<String> pred = new Predicate<>(){
      @Override public boolean test(String o){
        return !users.contains(o);
      }
    };
    final HashSet<String> mfa = new HashSet<String>((int)Math.ceil(users.size()/0.75));
    boolean changed = false;
    whitelistLock.writeLock().lock();
    try{
      changed|=whitelist.removeIf(pred);
    }finally{
      whitelistLock.writeLock().unlock();
    }
    mapLock.writeLock().lock();
    try{
      changed|=usernameEmailMappings.keySet().removeIf(pred);
      mfa.addAll(usernameEmailMappings.keySet());
    }finally{
      mapLock.writeLock().unlock();
    }
    otpLock.writeLock().lock();
    try{
      changed|=usernameOTPMappings.keySet().removeIf(pred);
      mfa.addAll(usernameOTPMappings.keySet());
    }finally{
      otpLock.writeLock().unlock();
    }
    cookieLock.writeLock().lock();
    try{
      changed|=cookieMappings.keySet().removeIf(new Predicate<String>(){
        @Override public boolean test(String s){
          final Matcher m = IPCookie.USERNAME_PATTERN.matcher(s);
          return !m.find() || !mfa.contains(m.group());
        }
      });
    }finally{
      cookieLock.writeLock().unlock();
    }
    return changed;
  }
  private static <T> T get(CompletableFuture<T> x, long timeout) throws InterruptedException, ExecutionException, CancellationException {
    try{
      return x.get(timeout, TimeUnit.MILLISECONDS);
    }catch(TimeoutException t){
      return null;
    }
  }
  /**
   * Cached for 30 seconds.
   * @return whether the specified user is controlled by the server, or {@code teapot} in the special case that the client should be prompted to configure MFA on the API server.
   */
  public static Boolean isControlledByAPI(String user, Boolean teapot){
    final String url = getServerURL();
    if (url==null){
      return false;
    }
    Long l = userAPICache.get(user);
    if (l!=null){
      boolean c = l>0;
      if (!c){
        l = -l;
      }
      if (System.currentTimeMillis()<l){
        return c;
      }else{
        userAPICache.remove(user);
      }
      l = null;
    }
    boolean result = false;
    try{
      // When JDK 21+ is used, we can put 'cli' in a try-with-resources statement.
      //HttpClient cli = HttpClient.newHttpClient();
      final CompletableFuture<HttpResponse<Void>> x = HttpClient.newHttpClient().sendAsync(
        HttpRequest.newBuilder()
          .uri(URI.create(url+"MFA/api"))
          .timeout(Duration.ofSeconds(3))
          .header("Content-Type", "application/x-www-form-urlencoded")
          .POST(HttpRequest.BodyPublishers.ofString("query=control&user="+MFAProvider.encodeURL(user)+"&key="+MFAProvider.encodeURL(serverAPIKey)+Initializer.licensedTo))
          .build(),
        HttpResponse.BodyHandlers.discarding(),
        null
      );
      HttpResponse<Void> res = null;
      try{
        while ((res = get(x, 500L))==null){
          if (Initializer.isKilled()){
            x.cancel(true);
            return false;
          }
        }
      }catch(Throwable t){
        x.cancel(true);
        //Initializer.log(t);
        return false;
      }
      final int stat = res.statusCode();
      if (stat==418){
        return teapot;
      }
      result = stat==200;
    }catch(Throwable t){
      Initializer.log(t);
      return false;
    }
    final long cur = System.currentTimeMillis();
    if (userAPICache.size()>512){
      userAPICache.values().removeIf(new java.util.function.Predicate<Long>(){
        @Override public boolean test(Long o){
          return Math.abs(o)<=cur;
        }
      });
    }
    userAPICache.put(user, (cur+30000L)*(result?1:-1));
    return result;
  }
  /**
   * @return {@code true} if the user needs to confirm an MFA code, or {@code false} if the user is allowed to bypass MFA.
   */
  public static boolean checkCookieAPI(String user, String ip){
    final String url = getServerURL();
    if (url==null){
      return true;
    }
    try{
      // When JDK 21+ is used, we can put 'cli' in a try-with-resources statement.
      //HttpClient cli = HttpClient.newHttpClient();
      final CompletableFuture<HttpResponse<Void>> x = HttpClient.newHttpClient().sendAsync(
        HttpRequest.newBuilder()
          .uri(URI.create(url+"MFA/api"))
          .timeout(Duration.ofSeconds(3))
          .header("Content-Type", "application/x-www-form-urlencoded")
          .POST(HttpRequest.BodyPublishers.ofString("query=bypass&user="+MFAProvider.encodeURL(user)+"&ip="+MFAProvider.encodeURL(ip)+"&key="+MFAProvider.encodeURL(serverAPIKey)+Initializer.licensedTo))
          .build(),
        HttpResponse.BodyHandlers.discarding(),
        null
      );
      HttpResponse<Void> res = null;
      try{
        while ((res = get(x, 500L))==null){
          if (Initializer.isKilled()){
            x.cancel(true);
            return true;
          }
        }
      }catch(Throwable t){
        x.cancel(true);
        //Initializer.log(t);
        return true;
      }
      return res.statusCode()!=200;
    }catch(Throwable t){
      Initializer.log(t);
      return true;
    }
  }
  /**
   * Successful responses are cached for 30 seconds when specified.
   * @return {@code true} if MFA was successfull confirmed, or {@code false} if the user entered an incorrect passcode.
   */
  public static boolean submitToAPI(String user, String code, String ip, boolean cache){
    final String url = getServerURL();
    if (url==null){
      return false;
    }
    final String key = cache?user+":"+ip+":"+code:null;
    if (cache){
      Long l = apiResponseCache.get(key);
      if (l!=null){
        if (System.currentTimeMillis()<l){
          return true;
        }else{
          apiResponseCache.remove(key);
        }
        l = null;
      }
    }
    boolean result = false;
    try{
      // When JDK 21+ is used, we can put 'cli' in a try-with-resources statement.
      //HttpClient cli = HttpClient.newHttpClient();
      final CompletableFuture<HttpResponse<Void>> x = HttpClient.newHttpClient().sendAsync(
        HttpRequest.newBuilder()
          .uri(URI.create(url+"MFA/api"))
          .timeout(Duration.ofSeconds(3))
          .header("Content-Type", "application/x-www-form-urlencoded")
          .POST(HttpRequest.BodyPublishers.ofString("query=submit&user="+MFAProvider.encodeURL(user)+"&ip="+MFAProvider.encodeURL(ip)+"&code="+MFAProvider.encodeURL(code)+"&key="+MFAProvider.encodeURL(serverAPIKey)+Initializer.licensedTo))
          .build(),
        HttpResponse.BodyHandlers.discarding(),
        null
      );
      HttpResponse<Void> res = null;
      try{
        while ((res = get(x, 500L))==null){
          if (Initializer.isKilled()){
            x.cancel(true);
            return false;
          }
        }
      }catch(Throwable t){
        x.cancel(true);
        //Initializer.log(t);
        return false;
      }
      result = res.statusCode()==200;
    }catch(Throwable t){
      Initializer.log(t);
      return false;
    }
    if (cache && result){
      final long cur = System.currentTimeMillis();
      if (apiResponseCache.size()>32){
        apiResponseCache.values().removeIf(new Predicate<Long>(){
          @Override public boolean test(Long o){
            return o<=cur;
          }
        });
      }
      apiResponseCache.put(key, cur+30000L);
    }
    return result;
  }
  public static void removeFromAPICache(String user, String code, String ip){
    apiResponseCache.remove(user+":"+ip+":"+code);
  }
  /**
   * @return {@code true} if the user needs to confirm an MFA code, or {@code false} if the user is allowed to bypass MFA.
   */
  public static boolean checkCookie(String user, String ip){
    if (!cookiesEnabled){
      return true;
    }
    cookieLock.readLock().lock();
    try{
      final IPCookie c = cookieMappings.get(user+"_"+ip);
      return c==null || c.expiry<=System.currentTimeMillis();
    }finally{
      cookieLock.readLock().unlock();
    }
  }
  public static void insertCookie(String user, String ip){
    if (!cookiesEnabled){
      return;
    }
    final String key = user+"_"+ip;
    cookieLock.writeLock().lock();
    try{
      final long cur = System.currentTimeMillis();
      cookieMappings.values().removeIf(new Predicate<IPCookie>(){
        @Override public boolean test(IPCookie o){
          return o.expiry<=cur;
        }
      });
      final IPCookie c = cookieMappings.get(key);
      if (c==null){
        cookieMappings.put(key, new IPCookie(key, cur+IPCookie.MAX_EXPIRY));
      }else{
        c.refresh(cur+IPCookie.MAX_EXPIRY);
      }
    }finally{
      cookieLock.writeLock().unlock();
    }
  }
  public static boolean codeAlreadySubmitted(String user, String code){
    final String key = user+":"+code;
    Long l = submittedCodeCache.get(key);
    final long cur = System.currentTimeMillis();
    if (l!=null){
      if (cur<l){
        return true;
      }else{
        submittedCodeCache.remove(key);
      }
      l = null;
    }
    if (submittedCodeCache.size()>32){
      submittedCodeCache.values().removeIf(new Predicate<Long>(){
        @Override public boolean test(Long o){
          return o<=cur;
        }
      });
    }
    submittedCodeCache.put(key, cur+180000L);
    return false;
  }
  public static void addFailedAttempt(String user){
    if (Config.emailEnabled && Config.containsEmailFor(user) || Config.containsOTPFor(user)){
      attempts.add(new Attempt(user));
      int x = getAttempts(user);
      if (x>10){
        x-=5;
        Iterator<Attempt> it = attempts.iterator();
        while (it.hasNext()){
          if (it.next().user.equals(user)){
            it.remove();
            if (--x<=0){
              break;
            }
          }
        }
      }
    }
  }
  public static boolean isRateLimited(String user){
    return getAttempts(user)>5;
  }
  private static int getAttempts(String user){
    final long lim = System.currentTimeMillis()-90000L;
    final Container<Integer> count = new Container<>(0);
    attempts.removeIf(new Predicate<Attempt>(){
      @Override public boolean test(Attempt o) {
        if (o.time<lim){
          return true;
        }else{
          if (o.user.equals(user)){
            ++count.x;
          }
          return false;
        }
      }
    });
    return count.x;
  }
  public static boolean isWhitelisted(String user){
    whitelistLock.readLock().lock();
    try{
      return whitelist.contains(user);
    }finally{
      whitelistLock.readLock().unlock();
    }
  }
  public static void setWhitelist(Collection<String> set){
    whitelistLock.writeLock().lock();
    try{
      whitelist.clear();
      whitelist.addAll(set);
    }finally{
      whitelistLock.writeLock().unlock();
    }
  }
  public static void printWhitelist(StringBuilder sb){
    sb.append('[');
    whitelistLock.readLock().lock();
    try{
      boolean first = true;
      for (String s: whitelist){
        if (first){
          first = false;
        }else{
          sb.append(',');
        }
        sb.append('"');
        sb.append(Utility.escapeJSON(s));
        sb.append('"');
      }
    }finally{
      whitelistLock.readLock().unlock();
    }
    sb.append(']');
  }
  public static void printEmails(StringBuilder sb){
    sb.append('[');
    mapLock.readLock().lock();
    try{
      boolean first = true;
      for (Map.Entry<String,String> e: usernameEmailMappings.entrySet()){
        if (first){
          first = false;
        }else{
          sb.append(',');
        }
        sb.append(Utility.format("{\"user\":\"$0\",\"email\":\"$1\"}", Utility.escapeJSON(e.getKey()), Utility.escapeJSON(e.getValue())));
      }
    }finally{
      mapLock.readLock().unlock();
    }
    sb.append(']');
  }
  public static void printOTPs(StringBuilder sb){
    sb.append('[');
    otpLock.readLock().lock();
    try{
      boolean first = true;
      for (Map.Entry<String,String> e: usernameOTPMappings.entrySet()){
        if (first){
          first = false;
        }else{
          sb.append(',');
        }
        sb.append('"').append(Utility.escapeJSON(e.getKey())).append('"');
      }
    }finally{
      otpLock.readLock().unlock();
    }
    sb.append(']');
  }
  public static void checkCookies(Set<String> users){
    final HashSet<String> set = new HashSet<>(Math.max((int)(users.size()/0.75), 16));
    mapLock.readLock().lock();
    try{
      set.addAll(usernameEmailMappings.keySet());
    }finally{
      mapLock.readLock().unlock();
    }
    set.removeAll(users);
    if (set.isEmpty()){
      return;
    }
    otpLock.readLock().lock();
    try{
      set.removeAll(usernameOTPMappings.keySet());
    }finally{
      otpLock.readLock().unlock();
    }
    if (set.isEmpty()){
      return;
    }
    cookieLock.writeLock().lock();
    try{
      cookieMappings.keySet().removeIf(new Predicate<String>(){
        @Override public boolean test(String s){
          final Matcher m = IPCookie.USERNAME_PATTERN.matcher(s);
          return !m.find() || set.contains(m.group());
        }
      });
    }finally{
      cookieLock.writeLock().unlock();
    }
  }
  public static void setEmails(Map<String,String> map){
    mapLock.writeLock().lock();
    try{
      usernameEmailMappings.clear();
      usernameEmailMappings.putAll(map);
    }finally{
      mapLock.writeLock().unlock();
    }
  }
  public static String setEmail(String username, String email){
    mapLock.writeLock().lock();
    try{
      if (email==null){
        return usernameEmailMappings.remove(username);
      }else{
        return usernameEmailMappings.put(username,email);
      }
    }finally{
      mapLock.writeLock().unlock();
    }
  }
  public static String getEmail(String username){
    mapLock.readLock().lock();
    try{
      return usernameEmailMappings.get(username);
    }finally{
      mapLock.readLock().unlock();
    }
  }
  public static boolean containsEmailFor(String username){
    mapLock.readLock().lock();
    try{
      return usernameEmailMappings.containsKey(username);
    }finally{
      mapLock.readLock().unlock();
    }
  }
  public static void setOTPs(Map<String,String> map){
    otpLock.writeLock().lock();
    try{
      usernameOTPMappings.clear();
      usernameOTPMappings.putAll(map);
    }finally{
      otpLock.writeLock().unlock();
    }
  }
  public static String setOTP(String username, String otp){
    if (otp==null && !containsEmailFor(username)){
      cookieLock.writeLock().lock();
      try{
        cookieMappings.keySet().removeIf(new Predicate<String>(){
          @Override public boolean test(String s){
            final Matcher m = IPCookie.USERNAME_PATTERN.matcher(s);
            return !m.find() || username.equalsIgnoreCase(m.group());
          }
        });
      }finally{
        cookieLock.writeLock().unlock();
      }
    }
    otpLock.writeLock().lock();
    try{
      if (otp==null){
        return usernameOTPMappings.remove(username);
      }else{
        return usernameOTPMappings.put(username,otp);
      }
    }finally{
      otpLock.writeLock().unlock();
    }
  }
  public static String getOTP(String username){
    otpLock.readLock().lock();
    try{
      return usernameOTPMappings.get(username);
    }finally{
      otpLock.readLock().unlock();
    }
  }
  public static boolean containsOTPFor(String username){
    otpLock.readLock().lock();
    try{
      return usernameOTPMappings.containsKey(username);
    }finally{
      otpLock.readLock().unlock();
    }
  }
  /**
   * Emails the given security code to the specified recipient.
   * @return {@code true} if the email was sent successfully or if email is not configured, or {@code false} if an exception was encountered while attempting to send the email.
   */
  public static boolean sendEmail(String recipient, SecurityCode code, long sleep){
    try{
      if (sleep>0){
        Thread.sleep(sleep);
      }
      EmailParametersBuilder pb = EmailServiceFactory.createParametersBuilder();
      pb.withSubject("WebCTRL MFA Security Code");
      pb.withToRecipients(new String[]{recipient});
      pb.withMessageContents("One-time passcode: "+String.valueOf(code.code));
      pb.withMessageMimeType("text/plain");
      EmailServiceFactory.getService().sendEmail(pb.build());
      return true;
    }catch(Throwable t){
      if (sleep<=0){
        Initializer.log(t);
      }
      return false;
    }
  }
  /**
   * Tests whether WebCTRL can connect to its email server.
   * @return whether the currently configured email server is working.
   */
  public static boolean testEmailServer(boolean log){
    try{
      final EmailServiceImpl serv = (EmailServiceImpl)EmailServiceFactory.getService();
      Field f = serv.getClass().getDeclaredField("emailServerConfiguration");
      f.setAccessible(true);
      EmailServerConfiguration emailServerConfiguration = (EmailServerConfiguration)f.get(serv);
      emailServerConfiguration.initialize();
      Properties emailProperties = new Properties();
      Method m = serv.getClass().getDeclaredMethod("setupPropertiesAndProtocol", Properties.class);
      m.setAccessible(true);
      String javaMailProtocol = (String)m.invoke(serv, emailProperties);
      m = serv.getClass().getDeclaredMethod("getAuthenticator", Properties.class, String.class);
      m.setAccessible(true);
      javax.mail.Authenticator auth = (javax.mail.Authenticator)m.invoke(serv, emailProperties, javaMailProtocol);
      m = serv.getClass().getDeclaredMethod("setupMailSession", Properties.class, javax.mail.Authenticator.class, String.class);
      m.setAccessible(true);
      Session mailSession = (Session)m.invoke(serv, emailProperties, auth, javaMailProtocol);
      Transport transport = mailSession.getTransport(javaMailProtocol);
      transport.connect(
          emailServerConfiguration.getMailHost(),
          emailServerConfiguration.getSmtpServerPort(),
          emailServerConfiguration.getUser(),
          emailServerConfiguration.getPassword()
      );
      transport.close();
      return true;
    }catch(Throwable t){
      if (log){
        Initializer.log(t);
      }
      return false;
    }
  }
  public static String generateNewAPIKey(){
    final byte[] arr = new byte[32];
    SecurityCode.rand.nextBytes(arr);
    apiKey = Utility.bytesToHex(arr, 0, arr.length);
    return apiKey;
  }
  public static String getServerURL(){
    long cur;
    if ((cur=System.currentTimeMillis())>nextURLCheck){
      nextURLCheck = cur+3600000L;
      loadServerURL();
    }
    return serverURL;
  }
  public static void resetServerURL(){
    nextURLCheck = 0;
  }
  public static void deleteServerURL(){
    serverURL = null;
    serverAPIKey = null;
    if (urlFile!=null){
      try{
        synchronized (Config.class){
          Files.deleteIfExists(urlFile);
        }
      }catch(Throwable t){
        Initializer.log(t);
      }
    }
  }
  private static void loadServerURL(){
    if (urlFile==null || !Files.exists(urlFile)){
      serverURL = null;
      serverAPIKey = null;
      return;
    }
    try{
      byte[] arr;
      synchronized(Config.class){
        arr = Files.readAllBytes(urlFile);
      }
      if (arr.length==0){
        serverURL = null;
        serverAPIKey = null;
      }else{
        final String s = new String(arr, java.nio.charset.StandardCharsets.UTF_8);
        int i = s.indexOf(' ');
        if (i<0){
          serverURL = null;
          serverAPIKey = null;
        }else{
          serverAPIKey = s.substring(i+1).trim();
          if (serverAPIKey.isEmpty()){
            serverURL = null;
            serverAPIKey = null;
          }else{
            serverURL = s.substring(0,i).trim().replaceFirst("(.*?)(?:/(?:MFA(?:/(?:api/?)?)?)?)?+$", "$1/");
          }
        }
      }
    }catch(Throwable t){
      serverURL = null;
      serverAPIKey = null;
      Initializer.log(t);
    }
  }
  /**
   * Load information from the saved data file.
   * @return whether data was loaded successfully.
   */
  public static boolean loadData(){
    if (mainFile==null){
      return false;
    }
    try{
      if (Files.exists(mainFile)){
        byte[] arr;
        synchronized(Config.class){
          arr = Files.readAllBytes(mainFile);
        }
        final SerializationStream s = new SerializationStream(arr);
        enforceMFA = s.readBoolean();
        allowServiceLogins = s.readBoolean();
        bypassOnEmailFailure = s.readBoolean();
        emailEnabled = s.readBoolean();
        cookiesEnabled = s.readBoolean();
        trustProxyHeaders = s.readBoolean();
        apiEnabled = s.readBoolean();
        apiKey = s.readString();
        int size = s.readInt();
        int i;
        mapLock.writeLock().lock();
        try{
          usernameEmailMappings.clear();
          String k,v;
          for (i=0;i<size;++i){
            k = s.readString();
            v = s.readString();
            usernameEmailMappings.put(k,v);
          }
        }finally{
          mapLock.writeLock().unlock();
        }
        size = s.readInt();
        otpLock.writeLock().lock();
        try{
          usernameOTPMappings.clear();
          String k,v;
          for (i=0;i<size;++i){
            k = s.readString();
            v = new String(Utility.obfuscate(s.readString().toCharArray()));
            usernameOTPMappings.put(k,v);
          }
        }finally{
          otpLock.writeLock().unlock();
        }
        size = s.readInt();
        whitelistLock.writeLock().lock();
        try{
          whitelist.clear();
          for (i=0;i<size;++i){
            whitelist.add(s.readString());
          }
        }finally{
          whitelistLock.writeLock().unlock();
        }
        if (!s.end()){
          Initializer.log("Data file corrupted.");
          return false;
        }
      }
      if (Files.exists(cookieFile)){
        byte[] arr;
        synchronized(Config.class){
          arr = Files.readAllBytes(cookieFile);
        }
        final SerializationStream s = new SerializationStream(arr);
        int size = s.readInt();
        final long cur = System.currentTimeMillis();
        final long lim = cur+IPCookie.MAX_EXPIRY;
        cookieLock.writeLock().lock();
        try{
          cookieMappings.clear();
          IPCookie v;
          for (int i=0;i<size;++i){
            v = new IPCookie(s.readString(),Math.min(s.readLong(),lim));
            if (v.expiry>cur){
              cookieMappings.put(v.user_ip,v);
            }
          }
        }finally{
          cookieLock.writeLock().unlock();
        }
        if (!s.end()){
          Initializer.log("Cookie file corrupted.");
          return false;
        }
      }
      return true;
    }catch(Throwable t){
      Initializer.log("Error occurred while loading data.");
      Initializer.log(t);
      return false;
    }
  }
  /**
   * Writes information to the saved data file.
   * @return whether data was saved successfully.
   */
  public static boolean saveData(){
    if (mainFile==null){
      return false;
    }
    try{
      SerializationStream s = new SerializationStream(1024, true);
      s.write(enforceMFA);
      s.write(allowServiceLogins);
      s.write(bypassOnEmailFailure);
      s.write(emailEnabled);
      s.write(cookiesEnabled);
      s.write(trustProxyHeaders);
      s.write(apiEnabled);
      s.write(apiKey);
      mapLock.readLock().lock();
      try{
        s.write(usernameEmailMappings.size());
        for (Map.Entry<String,String> e: usernameEmailMappings.entrySet()){
          s.write(e.getKey());
          s.write(e.getValue());
        }
      }finally{
        mapLock.readLock().unlock();
      }
      otpLock.readLock().lock();
      try{
        s.write(usernameOTPMappings.size());
        for (Map.Entry<String,String> e: usernameOTPMappings.entrySet()){
          s.write(e.getKey());
          s.write(new String(Utility.obfuscate(e.getValue().toCharArray())));
        }
      }finally{
        otpLock.readLock().unlock();
      }
      whitelistLock.readLock().lock();
      try{
        s.write(whitelist.size());
        for (String str: whitelist){
          s.write(str);
        }
      }finally{
        whitelistLock.readLock().unlock();
      }
      ByteBuffer buf = s.getBuffer();
      synchronized(Config.class){
        try(
          FileChannel out = FileChannel.open(mainFile, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        ){
          while (buf.hasRemaining()){
            out.write(buf);
          }
        }
      }
      return saveCookieData();
    }catch(Throwable t){
      Initializer.log(t);
      return false;
    }
  }
  public static boolean saveCookieData(){
    if (cookieFile==null){
      return false;
    }
    try{
      SerializationStream s = new SerializationStream(512, true);
      cookieLock.readLock().lock();
      try{
        s.write(cookieMappings.size());
        for (IPCookie c: cookieMappings.values()){
          s.write(c.user_ip);
          s.write(c.expiry);
        }
      }finally{
        cookieLock.readLock().unlock();
      }
      ByteBuffer buf = s.getBuffer();
      synchronized(Config.class){
        try(
          FileChannel out = FileChannel.open(cookieFile, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        ){
          while (buf.hasRemaining()){
            out.write(buf);
          }
        }
      }
      return true;
    }catch(Throwable t){
      Initializer.log(t);
      return false;
    }
  }
}
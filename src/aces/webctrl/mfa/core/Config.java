package aces.webctrl.mfa.core;
import com.controlj.green.core.email.*;
import javax.mail.*;
import java.util.*;
import java.util.concurrent.locks.*;
import java.nio.*;
import java.nio.file.*;
import java.nio.channels.*;
import java.lang.reflect.*;
public class Config {
  /** The path to the saved data file. */
  private static volatile Path file;
  private final static HashMap<String,String> usernameEmailMappings = new HashMap<>(32);
  private final static ReentrantReadWriteLock mapLock = new ReentrantReadWriteLock();
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
   * Sets the path to the saved data file and attempts to load any available data.
   */
  public static void init(Path file){
    Config.file = file;
    loadData();
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
  public static void printMappings(StringBuilder sb){
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
  public static void setMappings(Map<String,String> map){
    mapLock.writeLock().lock();
    try{
      usernameEmailMappings.clear();
      usernameEmailMappings.putAll(map);
    }finally{
      mapLock.writeLock().unlock();
    }
  }
  public static String setMapping(String username, String email){
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
      Authenticator auth = (Authenticator)m.invoke(serv, emailProperties, javaMailProtocol);
      m = serv.getClass().getDeclaredMethod("setupMailSession", Properties.class, Authenticator.class, String.class);
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
  /**
   * Load information from the saved data file.
   * @return whether data was loaded successfully.
   */
  public static boolean loadData(){
    if (file==null){
      return false;
    }
    try{
      if (Files.exists(file)){
        byte[] arr;
        synchronized(Config.class){
          arr = Files.readAllBytes(file);
        }
        final SerializationStream s = new SerializationStream(arr);
        enforceMFA = s.readBoolean();
        allowServiceLogins = s.readBoolean();
        bypassOnEmailFailure = s.readBoolean();
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
    if (file==null){
      return false;
    }
    try{
      final SerializationStream s = new SerializationStream(1024, true);
      s.write(enforceMFA);
      s.write(allowServiceLogins);
      s.write(bypassOnEmailFailure);
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
      whitelistLock.readLock().lock();
      try{
        s.write(whitelist.size());
        for (String str: whitelist){
          s.write(str);
        }
      }finally{
        whitelistLock.readLock().unlock();
      }
      final ByteBuffer buf = s.getBuffer();
      synchronized(Config.class){
        try(
          FileChannel out = FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
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
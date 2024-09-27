package aces.webctrl.mfa.core;
import java.security.SecureRandom;
public class SecurityCode {
  public final static SecureRandom rand = new SecureRandom();
  public final long expiry = System.currentTimeMillis()+300000L;
  public final int code = 100000+rand.nextInt(900000);
  public final byte[] token = new byte[32];
  public volatile int attempts = 3;
  public SecurityCode(){
    rand.nextBytes(token);
  }
  public String getToken(){
    return Utility.bytesToHex(token, 0, token.length);
  }
  public boolean isExpired(long currentTime){
    return currentTime>expiry;
  }
}
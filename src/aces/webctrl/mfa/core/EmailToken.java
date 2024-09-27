package aces.webctrl.mfa.core;
public class EmailToken {
  public final long expiry = System.currentTimeMillis()+300000L;
  public final byte[] token = new byte[32];
  public EmailToken(){
    SecurityCode.rand.nextBytes(token);
  }
  public String getToken(){
    return Utility.bytesToHex(token, 0, token.length);
  }
  public boolean isExpired(long currentTime){
    return currentTime>expiry;
  }
}
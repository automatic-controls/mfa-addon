package aces.webctrl.mfa.core;
public class IPCookie {
  public final static long MAX_EXPIRY = 604800000L; // 1 week
  public volatile String user_ip;
  public volatile long expiry;
  public IPCookie(String user_ip, long expiry) {
    this.user_ip = user_ip;
    this.expiry = expiry;
  }
  public IPCookie(String user_ip) {
    this.user_ip = user_ip;
    this.expiry = System.currentTimeMillis()+MAX_EXPIRY;
  }
  public void refresh(long expiry){
    this.expiry = expiry;
  }
}
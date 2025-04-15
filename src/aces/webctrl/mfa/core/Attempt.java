package aces.webctrl.mfa.core;
public class Attempt {
  public volatile String user;
  public volatile long time = System.currentTimeMillis();
  public Attempt(String user) {
    this.user = user;
  }
}
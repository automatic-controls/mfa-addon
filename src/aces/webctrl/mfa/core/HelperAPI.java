/*
  BSD 3-Clause License
  Copyright (c) 2022, Automatic Controls Equipment Systems, Inc.
  Contributors: Cameron Vogt (@cvogt729)
*/
package aces.webctrl.mfa.core;
import com.controlj.green.addonsupport.web.auth.AuthenticationManager;
import com.controlj.green.extensionsupport.Extension;
import com.controlj.green.core.ui.UserSession;
/**
 * Namespace which contains methods to access small sections of a few internal WebCTRL APIs.
 */
public class HelperAPI {
  /**
   * Specifies whether methods of this API should log stack traces generated from errors.
   */
  private final static boolean logErrors = true;
  /**
   * Terminates sessions for all foreign operators.
   * @return whether this method executed successfully.
   */
  public static boolean logoutAllForeign(){
    try{
      for (final UserSession session:UserSession.getAllUserSessions()){
        if (session.getOperator().isForeign()){
          session.close();
        }
      }
      return true;
    }catch(Throwable t){
      if (logErrors){ Initializer.log(t); }
      return false;
    }
  }
  /**
   * Activates the specified {@code WebOperatorProvider}.
   * @param addon specifies the name of the addon to activate.
   * @return an {@code Extension} object matching the given addon, or {@code null} if the addon cannot be found or if any error occurs.
   */
  public static Extension activateWebOperatorProvider(String addon){
    try{
      AuthenticationManager auth = new AuthenticationManager();
      for (Extension e:auth.findWebOperatorProviders()){
        if (addon.equals(e.getName())){
          auth.activateProvider(e);
          return e;
        }
      }
    }catch(Throwable t){
      if (logErrors){ Initializer.log(t); }
    }
    return null;
  }
  /**
   * Activates the default {@code WebOperatorProvider}.
   * @return whether this method executed successfully.
   */
  public static boolean activateDefaultWebOperatorProvider(){
    try{
      new AuthenticationManager().activateProvider(null);
      return true;
    }catch(Throwable t){
      if (logErrors){ Initializer.log(t); }
      return false;
    }
  }
}
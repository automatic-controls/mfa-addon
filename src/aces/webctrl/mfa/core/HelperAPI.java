/*
  BSD 3-Clause License
  Copyright (c) 2022, Automatic Controls Equipment Systems, Inc.
  Contributors: Cameron Vogt (@cvogt729)
*/
package aces.webctrl.mfa.core;
import java.util.*;
import com.controlj.green.addonsupport.web.auth.AuthenticationManager;
import com.controlj.green.extensionsupport.Extension;
import com.controlj.green.core.ui.UserSession;
import com.controlj.green.core.data.*;
import com.controlj.green.common.policy.*;
import com.controlj.green.datatable.util.CoreHelper;
/**
 * Namespace which contains methods to access small sections of a few internal WebCTRL APIs.
 */
public class HelperAPI {
  /**
   * Specifies whether methods of this API should log stack traces generated from errors.
   */
  private final static boolean logErrors = true;
  /**
   * @return a collection of all local WebCTRL operators where usernames are mapped to display names, or {@code null} if an error occurs.
   */
  public static Map<String,String> getLocalOperators(){
    try{
      return new CoreHelper().getOperatorList();
    }catch(Throwable t){
      Initializer.log(t);
      return null;
    }
  }
  /**
   * @return Whether the specified user exists in the system, case insensitive, and that the password validates.
   * If {@code pass} is {@code null}, the password is not validated.
   */
  public static boolean validateUser(String user, String pass){
    try(
      CoreDataSession cds = CoreDataSession.open(0);
    ){
      CoreNode op = cds.getExpectedNode("/trees/config/operators/operatorlist").getChildByAttribute(CoreNode.KEY, user, true);
      if (op==null){
        return false;
      }
      return pass==null || validatePassword(op, pass);
    }catch(CoreNotFoundException e){
      return false;
    }catch(Throwable t){
      if (logErrors){ Initializer.log(t); }
      return false;
    }
  }
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
  /**
   * @return whether the given password is correct.
   */
  public static boolean validatePassword(CoreNode operator, String password) throws CoreNotFoundException {
    return PolicyUtils_.rawMatches(operator.getChild("password").getValueString(), password);
  }
}
/**
 * We need this class to access a protected method {@code rawMatches(String,String)} of PolicyUtils.
 * The other option is {@code matches(String,String)}; however, this would create a delay on failed validation.
 * This no longer impacts WebCTRL9.0 since there is an added parameter to the matches method which specifies whether to delay or not,
 * but we keep this for backwards compatibility.
 */
class PolicyUtils_ extends PolicyUtils {
  public static boolean rawMatches(String digestedData, String clearData){
    return PolicyUtils.rawMatches(digestedData, clearData);
  }
}
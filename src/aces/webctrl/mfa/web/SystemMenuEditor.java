package aces.webctrl.mfa.web;
import aces.webctrl.mfa.core.*;
import com.controlj.green.addonsupport.access.*;
import com.controlj.green.addonsupport.web.menus.*;
public class SystemMenuEditor implements SystemMenuProvider {
  @Override public void updateMenu(Operator op, Menu menu){
    try{
      menu.addMenuEntry(MenuEntryFactory
        .newEntry("aces.webctrl.mfa.ChangeEmail")
        .display("Configure MFA")
        .action(Actions.openWindow("ChangeEmail"))
        .create()
      );
    }catch(Throwable t){
      Initializer.log(t);
    }
  }
}
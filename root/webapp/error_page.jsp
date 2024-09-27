<%@ page import="com.controlj.green.common.LanguageManager" %>
<%@ page import="java.util.Locale" %>
<%@ page import="com.controlj.green.common.CJIO" %>
<LINK REL=STYLESHEET TYPE="text/css" HREF="/_common/lvl5/skin/css/login_page_css.jsp">
<HTML>
<SCRIPT LANGUAGE="JavaScript" src="/_common/lvl5/util/browserapi.js"></SCRIPT>
<BODY SCROLL='NO' class="body1">
<table cellpadding="0" class="table1">
<tr class="row1">
<td class='col1'></td>
<td class='col2'></td>
<td class='col3'></td>
</tr>
<tr class="row2">
<td class='leftCol'>
</td>
<td style="text-align:center">
<table style="margin:0 auto"><tr><td><H2 style="text-align:center">
<%
String backURL = "/index.jsp";
Locale loc = LanguageManager.getSystemLocale();
String lang = request.getParameter("lang");
if (lang != null){
  loc = LanguageManager.createLocaleFromString(lang);
  backURL += "?operatorlocale="+loc;
}
String msg1 = com.controlj.green.common.CJIO.html(request.getParameter("m1"));
String msg2 = com.controlj.green.common.CJIO.html(request.getParameter("m2"));
%>
<%=msg1%> <br>
<%=msg2%> <br>
<input type='button' value='Back' onclick='location.href="<%=CJIO.js(backURL)%>"' tabindex='2' style="margin-top:1em">
</H2></td></tr></table>
</td>
<td class="rightCol">
<span id='actionVbar' style="position:relative; width:100%; height:100%"></span>
</td></tr>
<tr class="row3">
<td class="colA"></td>
<td class="colB">&nbsp;</td>
<td class="colC"></td>
</tr>
</table>
</BODY>
</HTML>
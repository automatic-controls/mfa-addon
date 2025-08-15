package aces.webctrl.mfa.core;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.*;
import java.time.*;
import java.time.format.*;
import javax.servlet.http.*;
import com.bastiaanjansen.otp.*;
/**
 * Contains various utility methods used throughout the application.
 */
public class Utility {
  public final static DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS").withZone(ZoneId.systemDefault());
  private final static Pattern SUBST_FORMATTER = Pattern.compile("\\$(\\d)");
  private final static Pattern LINE_ENDING = Pattern.compile("\\r?+\\n");
  private final static byte[] HEX_ARRAY = "0123456789ABCDEF".getBytes(StandardCharsets.US_ASCII);
  private final static Pattern FIRST_COMMA_LIST_PATTERN = Pattern.compile("^\\s*+([^,]+?)\\s*+(?:,|$)");
  private final static Pattern FIRST_FOR_LIST_PATTERN = Pattern.compile("(?:^|[,;])\\s*+for\\s*+=\\s*+([^,;]+?)\\s*+(?:$|[,;])", Pattern.CASE_INSENSITIVE);
  /**
   * Attempts to respect headers set by proxies and load balancers.
   */
  public static String getRemoteAddr(HttpServletRequest req){
    if (Config.trustProxyHeaders){
      Matcher m;
      String addr = req.getHeader("Forwarded");
      if (addr!=null){
        m = FIRST_FOR_LIST_PATTERN.matcher(addr);
        if (m.find()){
          addr = m.group(1);
        }else{
          addr = null;
        }
      }
      if (addr==null){
        addr = req.getHeader("X-Forwarded-For");
        if (addr!=null){
          m = FIRST_COMMA_LIST_PATTERN.matcher(addr);
          if (m.find()){
            addr = m.group(1);
          }else{
            addr = null;
          }
        }
        if (addr==null){
          addr = req.getHeader("X-Real-IP");
          if (addr==null || addr.isBlank()){
            addr = req.getRemoteAddr();
          }
        }
      }
      return addr.trim().toLowerCase();
    }else{
      return req.getRemoteAddr().toLowerCase();
    }
  }
  /**
   * @return whether the given code validates against the given TOTP URI string.
   */
  public static boolean checkCode(String OTP, String code) throws URISyntaxException {
    return TOTPGenerator.fromURI(new java.net.URI(OTP)).verify(code, 1);
  }
  /**
   * @return a new TOTP URI string for the given user.
   */
  @SuppressWarnings("deprecation")
  public static String createOTP(String user) throws URISyntaxException {
    return new TOTPGenerator.Builder(SecretGenerator.generate())
    .withHOTPGenerator(builder -> {
      builder.withPasswordLength(6);
      builder.withAlgorithm(HMACAlgorithm.SHA1);//deprecated, but Google Authenticator does not support any stronger algorithms
    })
    .withPeriod(java.time.Duration.ofSeconds(30))
    .build().getURI(Config.issuerName, user).toString();
  }
  /**
   * @return a hex string representation of the given bytes.
   */
  public static String bytesToHex(byte[] bytes, int offset, int length){
    if (bytes==null){
      return "";
    }
    if (offset>bytes.length){
      offset = bytes.length;
    }else if (offset<0){
      offset = 0;
    }
    if (length<0){
      length = 0;
    }
    int lim = offset+length;
    if (lim>bytes.length){
      lim = bytes.length;
      length = lim-offset;
    }
    if (length==0){
      return "";
    }
    byte[] hexChars = new byte[length<<1];
    int v,k;
    for (int j = 0; j < length; ++j) {
      v = bytes[j+offset] & 0xFF;
      k = j<<1;
      hexChars[k] = HEX_ARRAY[v >>> 4];
      hexChars[k+1] = HEX_ARRAY[v & 0x0F];
    }
    return new String(hexChars, StandardCharsets.UTF_8);
  }
  /**
   * @param epochMilli the number of milliseconds from 1970-01-01T00:00:00Z.
   * @return a formatted datetime {@code String} representing the specified instant in time.
   */
  public static String format(long epochMilli){
    return TIMESTAMP_FORMAT.format(Instant.ofEpochMilli(epochMilli));
  }
  /**
   * @return the first non-null argument.
   */
  public static String coalesce(final String... args){
    for (int i=0;i<args.length;++i){
      if (args[i]!=null){
        return args[i];
      }
    }
    return null;
  }
  /**
   * Replaces occurrences of {@code $n} in the input {@code String} with the nth indexed argument.
   * For example, {@code format("Hello $0!", "Beautiful")=="Hello Beautiful!"}.
   */
  public static String format(final String s, final Object... args){
    final String[] args_ = new String[args.length];
    for (int i=0;i<args.length;++i){
      args_[i] = args[i]==null?"":Matcher.quoteReplacement(args[i].toString());
    }
    return SUBST_FORMATTER.matcher(s).replaceAll(new java.util.function.Function<MatchResult,String>(){
      public String apply(MatchResult m){
        int i = Integer.parseInt(m.group(1));
        return i<args.length?args_[i]:"";
      }
    });
  }
  /**
   * @return a string which encodes the given list.
   * @see #decodeList(String)
   */
  public static String encodeList(List<String> list){
    int cap = list.size()<<2;
    for (String s:list){
      cap+=s.length();
    }
    StringBuilder sb = new StringBuilder(cap);
    for (String s:list){
      sb.append(s.replace("\\", "\\\\").replace(";", "\\;")).append(';');
    }
    return sb.toString();
  }
  /**
   * @return a list decoded from the given string.
   * @see #encodeList(List)
   */
  public static ArrayList<String> decodeList(String s){
    int len = s.length();
    int i,j,k,max=0;
    char c;
    boolean esc = false;
    for (i=0,j=0,k=0;i<len;++i){
      if (esc){
        esc = false;
        ++k;
      }else{
        c = s.charAt(i);
        if (c=='\\'){
          esc = true;
        }else if (c==';'){
          ++j;
          if (k>max){
            max = k;
          }
          k = 0;
        }else{
          ++k;
        }
      }
    }
    ArrayList<String> list = new ArrayList<String>(j);
    StringBuilder sb = new StringBuilder(max);
    esc = false;
    for (i=0;i<len;++i){
      c = s.charAt(i);
      if (esc){
        esc = false;
        sb.append(c);
      }else if (c=='\\'){
        esc = true;
      }else if (c==';'){
        list.add(sb.toString());
        sb.setLength(0);
      }else{
        sb.append(c);
      }
    }
    return list;
  }
  /**
   * Writes all bytes from the specified resource to the output file.
   */
  public static void extractResource(String name, Path out) throws Throwable {
    try(
      InputStream s = Utility.class.getClassLoader().getResourceAsStream(name);
      OutputStream t = Files.newOutputStream(out);
    ){
      int read;
      byte[] buffer = new byte[8192];
      while ((read = s.read(buffer, 0, 8192)) >= 0) {
        t.write(buffer, 0, read);
      }
    }
  }
  /**
   * Loads all bytes from the given resource and convert to a {@code UTF-8} string.
   * @return the {@code UTF-8} string representing the given resource.
   */
  public static String loadResourceAsString(String name) throws Throwable {
    byte[] arr;
    try(
      InputStream s = Utility.class.getClassLoader().getResourceAsStream(name);
    ){
      arr = s.readAllBytes();
    }
    return LINE_ENDING.matcher(new String(arr, java.nio.charset.StandardCharsets.UTF_8)).replaceAll(System.lineSeparator());
  }
  /**
   * Loads all bytes from the given resource and convert to a {@code UTF-8} string.
   * @return the {@code UTF-8} string representing the given resource.
   */
  public static String loadResourceAsString(ClassLoader cl, String name) throws Throwable {
    byte[] arr;
    try(
      InputStream s = cl.getResourceAsStream(name);
    ){
      arr = s.readAllBytes();
    }
    return LINE_ENDING.matcher(new String(arr, java.nio.charset.StandardCharsets.UTF_8)).replaceAll(System.lineSeparator());
  }
  /**
   * Escapes a {@code String} for usage in CSV document cells.
   * @param str is the {@code String} to escape.
   * @return the escaped {@code String}.
   */
  public static String escapeCSV(String str){
    if (str.indexOf(',')==-1 && str.indexOf('"')==-1 && str.indexOf('\n')==-1 && str.indexOf('\r')==-1){
      return str;
    }else{
      return '"'+str.replace("\"","\"\"")+'"';
    }
  }
  /**
   * Escapes a {@code String} for usage in HTML attribute values.
   * @param str is the {@code String} to escape.
   * @return the escaped {@code String}.
   */
  public static String escapeHTML(String str){
    if (str==null){
      return "";
    }
    int len = str.length();
    StringBuilder sb = new StringBuilder(len+16);
    char c;
    int j;
    for (int i=0;i<len;++i){
      c = str.charAt(i);
      j = c;
      if (j>=32 && j<127){
        switch (c){
          case '&':{
            sb.append("&amp;");
            break;
          }
          case '"':{
            sb.append("&quot;");
            break;
          }
          case '\'':{
            sb.append("&apos;");
            break;
          }
          case '<':{
            sb.append("&lt;");
            break;
          }
          case '>':{
            sb.append("&gt;");
            break;
          }
          default:{
            sb.append(c);
          }
        }
      }else if (j<1114111 && (j<=55296 || j>57343)){
        sb.append("&#").append(Integer.toString(j)).append(";");
      }
    }
    return sb.toString();
  }
  /**
   * Intended to escape strings for use in Javascript.
   * Escapes backslashes, single quotes, and double quotes.
   * Replaces new-line characters with the corresponding escape sequences.
   */
  public static String escapeJS(String str){
    if (str==null){
      return "";
    }
    int len = str.length();
    StringBuilder sb = new StringBuilder(len+16);
    char c;
    for (int i=0;i<len;++i){
      c = str.charAt(i);
      switch (c){
        case '\\': case '\'': case '"': {
          sb.append('\\').append(c);
          break;
        }
        case '\n': {
          sb.append("\\n");
          break;
        }
        case '\t': {
          sb.append("\\t");
          break;
        }
        case '\r': {
          sb.append("\\r");
          break;
        }
        case '\b': {
          sb.append("\\b");
          break;
        }
        case '\f': {
          sb.append("\\f");
          break;
        }
        default: {
          sb.append(c);
        }
      }
    }
    return sb.toString();
  }
  /**
   * Encodes a JSON string.
   */
  public static String escapeJSON(String s){
    if (s==null){ return "NULL"; }
    int len = s.length();
    StringBuilder sb = new StringBuilder(len+16);
    char c;
    String hex;
    int hl;
    for (int i=0;i<len;++i){
      c = s.charAt(i);
      switch (c){
        case '\\': case '/': case '"': {
          sb.append('\\').append(c);
          break;
        }
        case '\n': {
          sb.append("\\n");
          break;
        }
        case '\t': {
          sb.append("\\t");
          break;
        }
        case '\r': {
          sb.append("\\r");
          break;
        }
        case '\b': {
          sb.append("\\b");
          break;
        }
        case '\f': {
          sb.append("\\f");
          break;
        }
        default: {
          if (c>31 && c<127){
            sb.append(c);
          }else{
            //JDK17: hex = HexFormat.of().toHexDigits(c);
            hex = Integer.toHexString((int)c);
            hl = hex.length();
            if (hl<=4){
              sb.append("\\u");
              for (;hl<4;hl++){
                sb.append('0');
              }
              sb.append(hex);
            }
          }
        }
      }
    }
    return sb.toString();
  }
  /**
   * Reverses the order and XORs each character with 4.
   * The array is modified in-place, so no copies are made.
   * For convenience, the given array is returned.
   */
  public static char[] obfuscate(char[] arr){
    char c;
    for (int i=0,j=arr.length-1;i<=j;++i,--j){
      if (i==j){
        arr[i]^=4;
      }else{
        c = (char)(arr[j]^4);
        arr[j] = (char)(arr[i]^4);
        arr[i] = c;
      }
    }
    return arr;
  }
  /**
   * Converts a character array into a byte array.
   */
  public static byte[] toBytes(char[] arr){
    return java.nio.charset.StandardCharsets.UTF_8.encode(java.nio.CharBuffer.wrap(arr)).array();
  }
}
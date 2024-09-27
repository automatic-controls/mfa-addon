/*
  BSD 3-Clause License
  Copyright (c) 2022, Automatic Controls Equipment Systems, Inc.
  Contributors: Cameron Vogt (@cvogt729)
*/
package aces.webctrl.mfa.core;
import java.nio.charset.StandardCharsets;
import java.nio.*;
/**
 * Utility used for serializing and deserializing data.
 * This class does not support concurrency.
 */
public class SerializationStream {
  /** Raw data encapsulated by this stream. */
  public byte[] data;
  /** Index of the next byte to process in {@link #data}. */
  public int pos = 0;
  /** Whether the byte array should be dynamically enlarged when its capacity it reached. */
  public boolean autoResize = false;
  /**
   * Records a previous position.
   * @see {@link #mark()} and {@link #reset()}
   */
  private int mark = 0;
  /**
   * Empty constructor.
   */
  public SerializationStream(){}
  /**
   * Allocates an internal byte array with the given capacity.
   */
  public SerializationStream(int capacity, boolean autoResize){
    data = new byte[capacity];
    this.autoResize = autoResize;
  }
  /**
   * Wraps the given byte array.
   */
  public SerializationStream(byte[] data){
    this.data = data;
  }
  /**
   * Sets the current position to the last marked location, or {@code 0} if no position has been marked.
   * @see {@link #mark()}
   */
  public void reset(){
    pos = mark;
  }
  /**
   * Marks the current position.
   * @see {@link #reset()}
   */
  public void mark(){
    mark = pos;
  }
  /**
   * @return {@code true} if the current position exceeds the capacity of the internal byte array.
   */
  public boolean end(){
    return pos>=data.length;
  }
  /**
   * Resizes the internal byte array to enforce {@code data.length<=pos}.
   */
  public void trim(){
    if (data.length>pos){
      final byte[] arr = new byte[pos];
      System.arraycopy(data,0,arr,0,pos);
      data = arr;
    }
  }
  /**
   * Resizes the internal byte array to enforce {@code data.length>=len};
   */
  public void ensureCapacity(int len){
    if (data.length<len){
      int x = Math.max(data.length,8);
      while (x<len){
        x<<=1;
      }
      final byte[] arr = new byte[len];
      System.arraycopy(data,0,arr,0,data.length);
      data = arr;
    }
  }
  /**
   * Writes a single byte and increments the current position.
   * <ul><li>Required capacity: {@code 1}</li></ul>
   */
  public void write(byte b){
    if (autoResize){ ensureCapacity(pos+1); }
    data[pos++] = b;
  }
  /**
   * Writes either {@code (byte)0} or {@code (byte)1} depending on the given value.
   * <ul><li>Required capacity: {@code 1}</li></ul>
   */
  public void write(boolean b){
    write((byte)(b?1:0));
  }
  /**
   * Encodes and writes the given {@code int} to the stream.
   * <ul><li>Required capacity: {@code 4}</li></ul>
   */
  public void write(int x){
    if (autoResize){ ensureCapacity(pos+4); }
    for (int i=pos+3;;){
      data[i] = (byte)x;
      if (--i<pos){
        break;
      }else{
        x>>=8;
      }
    }
    pos+=4;
  }
  /**
   * Encodes and writes the given {@code long} to the stream.
   * <ul><li>Required capacity: {@code 8}</li></ul>
   */
  public void write(long x){
    if (autoResize){ ensureCapacity(pos+8); }
    for (int i=pos+7;;){
      data[i] = (byte)x;
      if (--i<pos){
        break;
      }else{
        x>>=8;
      }
    }
    pos+=8;
  }
  /**
   * Encodes and writes the given {@code double} to the stream.
   * <ul><li>Required capacity: {@code 8}</li></ul>
   */
  public void write(double x){
    write(Double.doubleToRawLongBits(x));
  }
  /**
   * Encodes and writes the given byte array to the stream.
   * <ul><li>Required capacity: {@code arr.length+4}</li></ul>
   */
  public void write(byte[] arr){
    write(arr,0,arr.length);
  }
  /**
   * Writes {@code length} bytes from the given array to the stream starting with the byte in position {@code offset}.
   * <ul><li>Required capacity: {@code length+4}</li></ul>
   */
  public void write(byte[] arr, int offset, int length){
    if (autoResize){ ensureCapacity(pos+length+4); }
    write(length);
    System.arraycopy(arr,offset,data,pos,length);
    pos+=length;
  }
  /**
   * Encodes and writes the given byte array to the stream.
   * <ul><li>Required capacity: {@code arr.length}</li></ul>
   */
  public void writeRaw(byte[] arr){
    writeRaw(arr,0,arr.length);
  }
  /**
   * Writes {@code length} bytes from the given array to the stream starting with the byte in position {@code offset}.
   * <ul><li>Required capacity: {@code length}</li></ul>
   */
  public void writeRaw(byte[] arr, int offset, int length){
    if (autoResize){ ensureCapacity(pos+length); }
    System.arraycopy(arr,offset,data,pos,length);
    pos+=length;
  }
  /**
   * Encodes the given string into UTF_8 bytes and writes to the stream.
   * <ul><li>Required capacity: {@code str.getBytes(StandardCharsets.UTF_8).length+4}</li></ul>
   */
  public void write(String str){
    write(str.getBytes(StandardCharsets.UTF_8));
  }
  /**
   * Reads a single byte from the stream.
   */
  public byte readByte(){
    return data[pos++];
  }
  /**
   * Reads a single byte from the stream.
   * @return {@code true} if the resulting byte is non-zero.
   */
  public boolean readBoolean(){
    return readByte()!=0;
  }
  /**
   * Reads an {@code int} from the stream.
   */
  public int readInt(){
    int x = 0;
    int i = pos;
    pos+=4;
    while (true){
      x|=(int)data[i]&0xFF;
      if (++i==pos){
        break;
      }else{
        x<<=8;
      }
    }
    return x;
  }
  /**
   * Reads a {@code long} from the stream.
   */
  public long readLong(){
    long x = 0;
    int i = pos;
    pos+=8;
    while (true){
      x|=(long)data[i]&0xFF;
      if (++i==pos){
        break;
      }else{
        x<<=8;
      }
    }
    return x;
  }
  /**
   * Reads a {@code double} from the stream.
   */
  public double readDouble(){
    return Double.longBitsToDouble(readLong());
  }
  /**
   * Reads a byte array from the stream.
   */
  public byte[] readBytes(){
    int len = readInt();
    byte[] arr = new byte[len];
    System.arraycopy(data,pos,arr,0,len);
    pos+=len;
    return arr;
  }
  /**
   * Reads a byte array from the stream into the given array starting at position {@code offset}.
   */
  public int readBytes(byte[] arr, int offset){
    int len = readInt();
    System.arraycopy(data,pos,arr,offset,len);
    pos+=len;
    return len;
  }
  /**
   * Reads a UTF_8 encoded string from the stream.
   */
  public String readString(){
    return new String(readBytes(), StandardCharsets.UTF_8);
  }
  /**
   * @return a {@code ByteBuffer} wrapping the data of this stream.
   */
  public ByteBuffer getBuffer(){
    return ByteBuffer.wrap(data,0,pos);
  }
}
package com.example.myapplication;

/*
 public class ServerClass1 extends AsyncTask<String, Integer, Boolean> {
 Socket socket;
 ServerSocket serverSocket;
 InputStream inputStream;
 OutputStream outputStream;
 @Override
 protected Boolean doInBackground(String... strings) {
 boolean result = true;
 try {
 serverSocket = new ServerSocket(8888);
 socket = serverSocket.accept();
 } catch (IOException e) {
 result = false;
 e.printStackTrace();
 }
 return result;
 }

 public void writeData(final byte[] bytes) {
 new Thread(new Runnable() {
 @Override
 public void run() {
 try {
 outputStream.write(bytes);
 } catch (IOException e) {
 e.printStackTrace();
 }
 }
 }).start();
 btnSend.setVisibility(View.VISIBLE);
 }

 @Override
 protected void onPostExecute(Boolean result) {
 if(result) {
 try {
 inputStream = socket.getInputStream();
 outputStream = socket.getOutputStream();
 } catch (IOException e) {
 e.printStackTrace();
 }
 //listener
 new Thread(new Runnable(){
 public void run() {
 byte[] buffer = new byte[1024];
 int x;
 while (socket!=null) {
 try {
 x = inputStream.read(buffer);
 if(x>0) {
 handler.obtainMessage(MESSAGE_READ,x,-1,buffer).sendToTarget();
 }
 } catch (IOException e) {
 e.printStackTrace();
 }
 }
 }
 }).start();
 btnSend.setVisibility(View.VISIBLE);
 } else {
 Toast.makeText(getApplicationContext(),"could not create sockets",Toast.LENGTH_SHORT).show();
 //restart socket assignment process
 }
 }

 }
 public class ClientClass1 extends AsyncTask<String, Integer, Boolean> {
 Socket socket;
 String hostAdd;
 InputStream inputStream;
 OutputStream outputStream;

 public ClientClass1(InetAddress hostAddress) {
 hostAdd = hostAddress.getHostAddress();
 socket = new Socket();
 }

 @Override
 protected Boolean doInBackground(String... strings) {
 boolean result = false;
 try {
 socket.connect(new InetSocketAddress(hostAdd, 8888), 5000);
 result = true;
 return result;
 } catch (IOException e) {
 e.printStackTrace();
 result = false;
 return result;
 }
 }

 public void writeData(final byte[] bytes) {
 new Thread(new Runnable() {
 @Override
 public void run() {
 try {
 outputStream.write(bytes);
 } catch (IOException e) {
 e.printStackTrace();
 }
 }
 }).start();
 btnSend.setVisibility(View.VISIBLE);
 }

 @Override
 protected void onPostExecute(Boolean result) {
 if(result) {
 try {
 inputStream = socket.getInputStream();
 outputStream = socket.getOutputStream();
 } catch (IOException e) {
 e.printStackTrace();
 }
 new Thread(new Runnable(){
 public void run() {
 byte[] buffer = new byte[1024];
 int x;
 while (socket!=null) {
 try {
 x = inputStream.read(buffer);
 if(x>0) {
 handler.obtainMessage(MESSAGE_READ,x,-1,buffer).sendToTarget();
 }
 } catch (IOException e) {
 e.printStackTrace();
 }
 }
 }
 }).start();
 btnSend.setVisibility(View.VISIBLE);
 } else {
 Toast.makeText(getApplicationContext(),"could not create sockets",Toast.LENGTH_SHORT).show();
 //restart socket assignment process
 }
 }
 }
 public class ServerClass2 extends AsyncTask{
 ServerSocket serverSocket;
 Socket socket;
 InputStream inputStream;
 OutputStream outputStream;

 @Override
 protected Object doInBackground(Object[] objects) {

 //while (bStarted) {

 try {
 serverSocket = new ServerSocket(8888);
 socket = serverSocket.accept();

 // send data
 String msg = writeMsg.getText().toString();
 outputStream = socket.getOutputStream();
 //String s = "Hello from Host " + Integer.toString(sendCount) + " " + msg;
 //sendCount++;
 outputStream.write(msg.getBytes());


 // Receive data
 inputStream = socket.getInputStream();
 byte[] buffer = new byte[1024];
 int bytes;
 bytes = inputStream.read(buffer);
 if (bytes > 0) {
 handler.obtainMessage(MESSAGE_READ, bytes, -1, buffer).sendToTarget();
 }

 outputStream.flush();
 outputStream.close();
 inputStream.close();

 serverSocket.close();
 socket.close();
 } catch (IOException e) {
 e.printStackTrace();
 }
 // while started

 return null;
 }

 }
 /**
 public class ClientClass2 extends AsyncTask{
 Socket socket;
 String hostAdd;
 OutputStream outputStream;
 InputStream inputStream;

 public ClientClass2(InetAddress hostAddress){
 hostAdd = hostAddress.getHostAddress();
 socket = new Socket();
 }

 @Override
 protected Object doInBackground(Object[] objects) {

 //while(bStarted) {
 try {
 socket = new Socket();
 socket.connect(new InetSocketAddress(hostAdd, 8888), 500);

 // send data
 String msg = writeMsg.getText().toString();
 outputStream = socket.getOutputStream();
 //String s = "Hello from Client " + Integer.toString(sendCount) + " " + msg;
 //sendCount++;
 outputStream.write(msg.getBytes());

 //receive data
 inputStream = null;
 inputStream = socket.getInputStream();
 byte[] buffer = new byte[1024];
 int bytes = -1;
 while(bytes == -1){
 bytes = inputStream.read(buffer);
 }
 if (bytes > 0) {
 handler.obtainMessage(MESSAGE_READ, bytes, -1, buffer).sendToTarget();
 }

 outputStream.flush();
 outputStream.close();
 inputStream.close();

 socket.close();

 } catch (IOException e) {
 e.printStackTrace();
 }
 // }//while bStarted
 return null;

 }

 }

 */
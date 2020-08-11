package com.example.myapplication;

import android.Manifest;
import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.IntentFilter;
import android.net.wifi.WifiManager;
import android.net.wifi.p2p.WifiP2pConfig;
import android.net.wifi.p2p.WifiP2pDevice;
import android.net.wifi.p2p.WifiP2pDeviceList;
import android.net.wifi.p2p.WifiP2pInfo;
import android.net.wifi.p2p.WifiP2pManager;
import android.os.AsyncTask;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Message;
import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.Signature;

import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;

import com.gun0912.tedpermission.PermissionListener;
import com.gun0912.tedpermission.TedPermission;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import static javax.crypto.Cipher.ENCRYPT_MODE;
import static javax.crypto.Cipher.getInstance;

@RequiresApi(api = Build.VERSION_CODES.O)
public class MainActivity extends AppCompatActivity {

    //UI elements
    Button btnDiscover, btnSend;
    ListView listView;
    TextView connectionStatus;
    ListView MessageHistory;
    EditText writeMsg;

    ArrayList<String> message_history = new ArrayList<String>();
    ArrayAdapter myAdapter1;

    WifiManager wifiManager;
    WifiP2pManager mManager;
    WifiP2pManager.Channel mChannel;

    BroadcastReceiver mReceiver;
    IntentFilter mIntentFilter;

    List<WifiP2pDevice> peers = new ArrayList<WifiP2pDevice>();
    String[] deviceNameArray;
    WifiP2pDevice[] deviceArray;
    static final int MESSAGE_READ = 1;

    ServerClass serverClass;
    ClientClass clientClass;
    SendReceive sendReceive;

    public Boolean StartofConversation = true;
    public Boolean FirstSentMessage =true;
    boolean isServer =false;
    boolean keyReceived =false;
    boolean keySent = false;
    boolean BothKeysExchanged = false;
    boolean stagetwo = false;
    boolean DecideonP =false;
    boolean DecideonG = false;
    boolean NonceReceived =false;
    boolean NonceCheck =false;
    boolean HideMyKey = false;
    boolean StageTwoComplete =false;
    boolean stagethree =false;
    boolean NonceSent =false;
    boolean StageThreeComplete =false;
    boolean SavedNonce =false;

    boolean MC1Sent =false;
    boolean MC1Received =false;
    boolean MC2Sent = false;
    boolean MC2Received =false;
    boolean MC3Sent =false;
    boolean MC3Received =false;
    boolean DontEncryptSig = false;
    boolean StageThreePart2Start = false;
    String Placeholder = null;
    private String NonceMC2;

    String Nonce =GenerateNonce();
    String CheckNonce;
    String ExtractedNonce = "";

     PublicKey publicKey;
     PrivateKey privateKey;
     KeyPair kp;
    String RecipientKey;
    byte[] privateKeyBytes;
    byte[] publicKeyBytes;
     String privateKeyBytesBase64;
     String publicKeyBytesBase64;
     PublicKey RecipientKeyy;



    private Cipher cipher,decipher;
    private SecretKeySpec secretKeySpec;

   // String Nonce=GenerateNonce(); //nei or nej
    private byte[] encryptionKey = {9,115,51,86,105,4,-31,-23,-68,88,17,20,3,-105,119,53} ; //generate key using my proto, here is just a dummy key
    private static Context mContext;
    private boolean StageThreeCompletePart1 = false;

    // @RequiresApi(api = Build.VERSION_CODES.O)
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        initialWork();
        exqListener();

        try {
            cipher = Cipher.getInstance("AES"); //final stage once secret is established
            decipher = Cipher.getInstance("AES");
            secretKeySpec = new SecretKeySpec(encryptionKey, "AES");
        } catch (NoSuchAlgorithmException e) { e.printStackTrace(); } catch (NoSuchPaddingException e) { e.printStackTrace(); }
    }

    Handler handler = new Handler(new Handler.Callback() {


        @RequiresApi(api = Build.VERSION_CODES.O)
        @Override
        public boolean handleMessage(Message message) {
            switch (message.what) {
                case MESSAGE_READ:

                    byte[] readBuff = (byte[]) message.obj;
                    String tempMsg = new String(readBuff, 0, message.arg1);


                    //refresh
                    if (FirstSentMessage && !keyReceived){ //&& !BothKeysExchanged) {
                        if(tempMsg.length() <100){
                            Toast.makeText(MainActivity.this,"Key Size too small",Toast.LENGTH_LONG).show();
                        }else {
                            RecipientKey = AESDecryptionMethod(tempMsg); //first actual message is ignored and replaced w/ pub key
                            Toast.makeText(MainActivity.this, "Key Received", Toast.LENGTH_SHORT).show();
                            keyReceived = true;
                            FirstSentMessage = false;

                            if (keySent) {
                                BothKeysExchanged = true;
                                Toast.makeText(MainActivity.this, "Both Public Keys Exchanged", Toast.LENGTH_SHORT).show(); //only one device will show this
                            }
                        }

                    }
                    else {


                        if(tempMsg==null){
                           Toast.makeText(MainActivity.this,"INVALID MESSAGE",Toast.LENGTH_SHORT).show();
                    }

                        else {
                           // Toast.makeText(MainActivity.this,"Incoming Message",Toast.LENGTH_SHORT).show();

                            String Msg = decryptRSAToString(tempMsg, privateKeyBytesBase64,true);

                            if(StageThreeCompletePart1){
                                //message_history.add("IM HERE");
                                tempMsg = tempMsg + Placeholder; //append both parts of string

                                tempMsg = decryptRSAToString(tempMsg,privateKeyBytesBase64,true);
                                message_history.add("Round 1 " + tempMsg);
                                tempMsg = decryptRSAToString(tempMsg, RecipientKey,false);
                                message_history.add("Round 2 " + tempMsg);
                                //message_history.add("Attempting double decryption");
                                Msg = tempMsg;
                                StageThreeCompletePart1 = false;

                                //ExtractedNonce = Msg.substring(0, 64); //get first 64 characters i.e Nonce // check here for my nonce
                                //String NonceMC2 = Msg.substring(66,Msg.length());
                                // message_history.add("[THEM  " + TimeStamp() + "]  " + "MC2: " + tempMsg1 + tempMsg1.length()); //length of Cleartext 0

                                //if(ExtractedNonce.equals(Nonce)){ //if nonce received is nonce I sent
                                //  message_history.add("NONCES MATCH!");
                                //}else{
                                //  message_history.add("Nonce: " + Nonce + " Extracted Nonce: " + ExtractedNonce + "MC2NONCE " + NonceMC2);
                                //}
                            }

                            if((!StageThreeComplete)){

                            if (Msg.contains(":")) {//(Msg.startsWith("0C:E0:DC") | Msg.startsWith("A4:50:46")|Msg.startsWith("EE:12:CC") | Msg.startsWith("A2:0B")) {//hardcode check
                              NonceReceived = true;
                              MC1Received = true;


                                CheckNonce = Msg.substring(20,Msg.length()); //define a substring that starts at the end of the mac address + space. The remaining is nonce sent by partner
                              //Toast.makeText(MainActivity.this, "Nonce Received", Toast.LENGTH_SHORT).show();
                                message_history.add("NONCE RECEIVED: " + CheckNonce);
                               stagethree =true; //Ive received MC1 i need to send MC2
                               //message_history.add("[THEM  " + TimeStamp() + "]  " + Msg); //will not display a message unless it is encrypted and contains correct MAC address
                                Toast.makeText(MainActivity.this, "Please Send MC2 ", Toast.LENGTH_SHORT).show();
                            }


                            ///NEED TO HANDLE MC2

                                if(MC1Sent && !StageThreeComplete && !MC1Received && NonceSent && !NonceReceived) { //If i Sent MC1 I then need to handle MC2


                                    //VerifySign(tempMsg);
                                    //Msg = decryptRSAToString(Msg,privateKeyBytesBase64,true);
                                    Msg = decryptRSAToString(tempMsg, RecipientKey,false);//decrypt inner message with their public key as inner message was encrypted with Partners priv key

                                    ExtractedNonce = Msg.substring(0, 64); //get first 64 characters i.e Nonce // check here for my nonce
                                    NonceMC2 = Msg.substring(66,Msg.length());
                                    // message_history.add("[THEM  " + TimeStamp() + "]  " + "MC2: " + tempMsg1 + tempMsg1.length()); //length of Cleartext 0

                                    if(ExtractedNonce.equals(Nonce)){ //if nonce received is nonce I sent
                                        message_history.add("NONCES MATCH!");
                                    }else{
                                        message_history.add("Nonce: " + Nonce + " Extracted Nonce: " + ExtractedNonce + "MC2NONCE " + NonceMC2);
                                    }
                                    StageThreeComplete = true; //never enter this loop again
                                   // StageThreeCompletePart1 = true; //Toast.makeText(MainActivity.this,"PART1 "+ StageThreeCompletePart1,Toast.LENGTH_LONG).show();
                                }




                                message_history.add("[THEM  " + TimeStamp() + "]  " + Msg);

                            }else{
                                message_history.add("[THEM  " + TimeStamp() + "]  " + Msg); //not in stage 3 so PGP
                            }

                            myAdapter1.notifyDataSetChanged(); //refresh
                        }

                    }

                    break;

                default:
                    throw new IllegalStateException("Unexpected value: " + message.what);
            }
            return true;
        }
    });

    @Override
    protected void onRestoreInstanceState(@NonNull Bundle savedInstanceState) {
        super.onRestoreInstanceState(savedInstanceState);//setContentView(R.layout.activity_main);//initialWork();//exqListener();
        peers.clear();
    }

    private void exqListener() {
        btnDiscover.setOnClickListener(new View.OnClickListener() {
            //@RequiresApi(api = Build.VERSION_CODES.ICE_CREAM_SANDWICH)
            @SuppressLint("MissingPermission")
            @Override
            public void onClick(View view) {

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    EnableRuntimePermission(); //ask user for permission to use Wi-Fi & Location
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    mManager.discoverPeers(mChannel, new WifiP2pManager.ActionListener() {
                        //@RequiresApi(api = Build.VERSION_CODES.O)
                        @Override
                        public void onSuccess() {
                            connectionStatus.setText("Discovery Started");
                        }
                       // @RequiresApi(api = Build.VERSION_CODES.O)
                        @Override
                        public void onFailure(int i) {
                            connectionStatus.setText("Discovery Failed, Check Location is ON");
                        }
                    });
                }
            }
        });

        listView.setOnItemClickListener(new AdapterView.OnItemClickListener() {    //permissions defined in manifest
            @SuppressLint("MissingPermission")
            @Override
            public void onItemClick(AdapterView<?> adapterView, View view, int i, long l) {
                final WifiP2pDevice device = deviceArray[i];
                WifiP2pConfig config = new WifiP2pConfig();
                config.deviceAddress = device.deviceAddress;

                mManager.connect(mChannel, config, new WifiP2pManager.ActionListener() {
                    @SuppressLint("MissingPermission")
                    @Override
                    public void onSuccess() {
                        Toast.makeText(getApplicationContext(), "Connected to " + device.deviceName, Toast.LENGTH_SHORT).show();
                    }
                    @SuppressLint("MissingPermission")
                    @Override
                    public void onFailure(int i) {
                        Toast.makeText(getApplicationContext(), "Not connected", Toast.LENGTH_SHORT).show();
                    }
                });
            }
        });

        btnSend.setOnClickListener(new View.OnClickListener() {
            @RequiresApi(api = Build.VERSION_CODES.O)
            @Override
            public void onClick(View v) {

                String msg = writeMsg.getText().toString();

                String ClearText = msg;


                if (StartofConversation) { //Toast.makeText(MainActivity.this,"Start of Conversation",Toast.LENGTH_SHORT).show();
                    msg = AESEncryptionMethod(publicKeyBytesBase64);
                    keySent = true;
                    try {
                        Thread.sleep(1000);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    } //delay
                    StartofConversation = false; //set this boolean to false
                    HideMyKey = true;
                }

                if (!StageTwoComplete && stagetwo) {// && BothKeysExchanged){ //now we can send the encrypted nonce + mac address //by using a separate boolean we can make multiple passes over this func without skipping a step
                    if (keyReceived && keySent && (!NonceReceived || !NonceSent)) {
                        msg = GetMacAddress() + "   " + Nonce; //overwrite message
                        ClearText = msg;
                        // msg = Nonce + "     " + GetMacAddress();
                        NonceSent = true;
                        MC1Sent = true;
                        Toast.makeText(MainActivity.this, "Nonce Sent", Toast.LENGTH_SHORT).show();
                        try {
                            Thread.sleep(1000);
                        } catch (InterruptedException e) {
                            e.printStackTrace();
                        } //delay
                    } else {
                        Toast.makeText(MainActivity.this, "ELSE", Toast.LENGTH_SHORT).show();
                        //msg = writeMsg.getText().toString();
                    }//just in case msg
                    StageTwoComplete = true;
                }

                if (StageThreePart2Start){
                    msg = encryptRSAToString("HI", privateKeyBytesBase64, false);
                    ClearText = "Hi Part 2";
                    //msg = msg.substring(msg.length()/2,msg.length());
                    StageThreePart2Start = false;
                }



                if (!StageThreeComplete && !NonceSent && NonceReceived) { //doesn't enter this unless MC1 was RECEIVED
                    ClearText =CheckNonce + " " + Nonce;
                     msg = encryptRSAToString(ClearText,privateKeyBytesBase64,false); //their nonce + g^j mod p encrypt with my priv key so partner can decrypt w/ my public key + CheckNonce +Nonce +

                    MC2Sent = true;
                    MC2Received = false;
                    BothKeysExchanged = true;
                    StageThreeComplete = true; //never enter this loop again
                    DontEncryptSig = true;
                  //  StageThreePart2Start = true;
                }




                    //Post Start of Conversation

                    if (BothKeysExchanged) { //only encrypt if Key received

                        if (msg != null && msg.length() != 0) {
                            if (!DontEncryptSig) {
                                msg = encryptRSAToString(msg, RecipientKey, true);
                               // Toast.makeText(MainActivity.this, "Length of " + msg.length(), Toast.LENGTH_LONG).show();
                                sendtask t3 = new sendtask(msg);

                               // if (StageThreeComplete) {
                                 //   message_history.add("Double Encrypted?" + msg + msg.length());
                                // }

                                try {
                                    Thread.sleep(500);
                                } catch (InterruptedException e) {
                                    e.printStackTrace();
                                } //delay

                                t3.execute(); //start new thread
                            } else {
                                message_history.add(msg);

                                Toast.makeText(MainActivity.this, "Unencrypted", Toast.LENGTH_SHORT).show(); //sent using pre-key -> basically no encryption
                                sendtask t3 = new sendtask(msg);
                                t3.execute();
                                DontEncryptSig = false;
                            }
                        } else {
                            Toast.makeText(MainActivity.this, "NULL MESSAGE", Toast.LENGTH_LONG).show();
                        }
                    } else {
                        if (!HideMyKey) {
                            Toast.makeText(MainActivity.this, "WARNING: Unencrypted", Toast.LENGTH_SHORT).show(); //sent using pre-key -> basically no encryption
                        }
                        sendtask t3 = new sendtask(msg); //  Toast.makeText(MainActivity.this, "keyReceived" + " "+ keyReceived  +" " +keySent  +" Both "+BothKeysExchanged  +" 2: " +stagetwo, Toast.LENGTH_SHORT).show();
                        t3.execute(); //start new thread

                        if (RecipientKey != null && RecipientKey.length() > 100) {
                            keyReceived = true;

                            if (keySent) {
                                BothKeysExchanged = true;
                                // Toast.makeText(MainActivity.this, "Public Keys Exchanged", Toast.LENGTH_SHORT).show();
                                stagetwo = true; //no danger of rerunnning stage 2 as stagetwocomplete flag set to true but we want to run on second attempt
                            }

                        } else {
                            Toast.makeText(MainActivity.this, "Need Partner Key/Key Invalid", Toast.LENGTH_SHORT).show();
                        }

                    }


                if (!HideMyKey) {
                    //try { Thread.sleep(100); } catch (InterruptedException e) { e.printStackTrace(); }
                    message_history.add("[YOU  " + TimeStamp() + "]  " + (ClearText)); //Update message history, no need to encrypt/decrypt client side messages
                    myAdapter1.notifyDataSetChanged(); //refresh

                } else {
                    Toast.makeText(MainActivity.this, "Hidden Your Key", Toast.LENGTH_SHORT).show();
                    HideMyKey = false;
                }
            }

          //  secretKeySpec = new SecretKeySpec(encryptionKey, "AES"); update encryption key, encryptionKey = sessionkey.getBytes()

            //MessageDigest sha = MessageDigest.getInstance("SHA-1");
            //key = sha.digest(sessionkey.getBytes("UTF-8"));
            //key = Arrays.copyOf(key, 16); // use only first 128 bit
           // secretKeySpec = new SecretKeySpec(key, "AES");
        });
    }

    //@RequiresApi(api = Build.VERSION_CODES.O)
    private void initialWork() {
        // Read in UI by ID defined in the XML
        btnDiscover = findViewById(R.id.discover);
        btnSend = findViewById(R.id.sendButton);
        listView = findViewById(R.id.peerListView);
        MessageHistory = findViewById(R.id.MessageHistory);
        connectionStatus = findViewById(R.id.connectionStatus);
        writeMsg = findViewById(R.id.writeMsg);

        myAdapter1 = new ArrayAdapter<String>(this,android.R.layout.simple_list_item_1,message_history);
        MessageHistory.setAdapter(myAdapter1); //in order to use listviews in android you need an adapter

        ///wifi manager
        wifiManager = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);// initialise the wifi manager
        mManager = (WifiP2pManager) getSystemService(Context.WIFI_P2P_SERVICE);
        mChannel = mManager.initialize(this, getMainLooper(), null);
        mReceiver = new WiFiDirectBroadcastReceiver(mManager, mChannel, this);

        //intents
        mIntentFilter = new IntentFilter();
        mIntentFilter.addAction(WifiP2pManager.WIFI_P2P_STATE_CHANGED_ACTION);
        mIntentFilter.addAction(WifiP2pManager.WIFI_P2P_PEERS_CHANGED_ACTION);
        mIntentFilter.addAction(WifiP2pManager.WIFI_P2P_CONNECTION_CHANGED_ACTION);
        mIntentFilter.addAction(WifiP2pManager.WIFI_P2P_THIS_DEVICE_CHANGED_ACTION);


        kp =  getKeyPair(); //generate key pair from spec

        privateKey =kp.getPrivate();//get priv key
        privateKeyBytes = privateKey.getEncoded();
        privateKeyBytesBase64 = new String(Base64.encode(privateKeyBytes, Base64.DEFAULT));
        RecipientKey =null;


        publicKey =kp.getPublic(); //read public key
        publicKeyBytes = publicKey.getEncoded(); //bytes
        publicKeyBytesBase64 = new String(Base64.encode(publicKeyBytes, Base64.DEFAULT)); //process to string for sending



    }

    WifiP2pManager.PeerListListener peerListListener = new WifiP2pManager.PeerListListener() {
        @Override
        public void onPeersAvailable(WifiP2pDeviceList peerlist) {

            if (!peerlist.getDeviceList().equals(peers)) {
                peers.clear(); //remove old peers
                peers.addAll(peerlist.getDeviceList()); //get new peer list
                deviceNameArray = new String[peerlist.getDeviceList().size()];
                deviceArray = new WifiP2pDevice[peerlist.getDeviceList().size()];
                int index = 0;

                for (WifiP2pDevice device : peerlist.getDeviceList()) {
                    deviceNameArray[index] = device.deviceName;
                    deviceArray[index] = device;
                    index++;
                }
                ArrayAdapter<String> adapter = new ArrayAdapter<String>(getApplicationContext(), android.R.layout.simple_list_item_1, deviceNameArray);
                listView.setAdapter(adapter);
                //adapter.notifyDataSetChanged(); //?
            }
            if (peers.size() == 0) {
                Toast.makeText(getApplicationContext(), "No Devices Found ", Toast.LENGTH_SHORT).show();  // tell the user no devices where found,

                return;
            }
        }
    };

    WifiP2pManager.ConnectionInfoListener connectionInfoListener = new WifiP2pManager.ConnectionInfoListener() {
        @Override
        public void onConnectionInfoAvailable(WifiP2pInfo wifiP2pInfo) {
            final InetAddress groupOwnerAddress = wifiP2pInfo.groupOwnerAddress;
            if (wifiP2pInfo.groupFormed && wifiP2pInfo.isGroupOwner) {

                connectionStatus.setText("Host");
                serverClass = new ServerClass();
                isServer = true;
                serverClass.start(); //start thread

            } else if (wifiP2pInfo.groupFormed) {

                connectionStatus.setText("Client");
                clientClass = new ClientClass(groupOwnerAddress);
                isServer =false;
                clientClass.start(); //start thread
            }
            String currentTime;
            String currentDate = new SimpleDateFormat("dd-MM-yyyy  ", Locale.getDefault()).format(new Date());
            currentTime = TimeStamp();
            message_history.add("Conversation Start  " + currentDate + currentTime);
            btnSend.setVisibility(View.VISIBLE); //only show button if ready to send


        }
    };

    @Override
    protected void onPause() { //code to be run if user leaves the app
        super.onPause();
        unregisterReceiver(mReceiver); }

    @Override
    protected void onResume() {
        super.onResume();
        registerReceiver(mReceiver, mIntentFilter); }

    @Override
    protected void onDestroy() {            //code to be run before activity is destroyed

        connectionStatus.setText("Off"); //reset
        btnSend.setVisibility(View.GONE); //hide send button this is to prevent user sending anything

        ///Close all input output streams and close all sockets
        try {
            sendReceive.outputStream.flush();
            sendReceive.outputStream.close();
            sendReceive.inputStream.close();

            if(isServer){
                serverClass.serverSocket.close();
                serverClass.socket.close();
            }else
                clientClass.socket.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        super.onDestroy();
    }

    public class ServerClass extends Thread {

        Socket socket;
        ServerSocket serverSocket;

        @Override
        public void run() {
            try {
                serverSocket = new ServerSocket(8888); //arbitrarily chosen socket
                socket = serverSocket.accept();
                sendReceive = new SendReceive(socket);
                sendReceive.start(); //start thread
            } catch (IOException e) {
                e.printStackTrace();
                try {
                    serverSocket.close(); //force close socket on error
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }

    }

    public class ClientClass extends Thread {
        Socket socket;
        String hostAdd;

        public ClientClass(InetAddress hostAddress) {
            hostAdd = hostAddress.getHostAddress();
            socket = new Socket(); }

        @Override
        public void run() {
                try {
                    socket.connect(new InetSocketAddress(hostAdd, 8888), 500); //Please try to find the solution how to close socket while disconnecting the device.
                    sendReceive = new SendReceive(socket);
                    sendReceive.start();
                } catch (IOException e) {
                    try {
                        socket.close(); //force close socket in case of error
                    } catch (IOException ex) {
                        ex.printStackTrace();
                    }
                    e.printStackTrace();
                }// super.run();
            }
    }

    private class SendReceive extends Thread {
        private Socket socket;
        private InputStream inputStream;
        private OutputStream outputStream;


        public SendReceive(Socket skt) {
            socket = skt;
            socket = skt;
            try {
                inputStream = socket.getInputStream();
                outputStream = socket.getOutputStream();
                try { Thread.sleep(100); } catch (InterruptedException e) { e.printStackTrace(); } //add delay
            } catch (IOException e) { e.printStackTrace();}
        }

        @Override
        public void run() {
            byte[] buffer = new byte[1024];
            int bytes;
            while (socket != null) {
                try {
                    bytes = inputStream.read(buffer);
                    if (bytes > 0) { //i.e if there is a message
                        handler.obtainMessage(MESSAGE_READ, bytes, -1, buffer).sendToTarget();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        public void write(final byte[] bytes)
        {
            new Thread(new Runnable(){

                @Override
                public void run()
                {
                    try
                    { outputStream.write(bytes); }
                    catch (IOException e) {e.printStackTrace();}
                }}).start();
        }
    }

    @SuppressLint("StaticFieldLeak")
    public class sendtask extends AsyncTask<Void, Void, Void> {
        String message;

        sendtask(String msg) {
            message=(msg);
        }

        @RequiresApi(api = Build.VERSION_CODES.O)
        @Override
        protected Void doInBackground(Void... arg0) {
           sendReceive.write((message).getBytes());
            return null;
        }
        @Override
        protected void onPostExecute(Void result) { //after task executed
            super.onPostExecute(result);
        }
    }

    public void EnableRuntimePermission(){
        String[] perms ={Manifest.permission.ACCESS_FINE_LOCATION,Manifest.permission.READ_PHONE_STATE}; // Permissions I want to ask
        PermissionListener permissionListener = new PermissionListener() {
            @Override
            public void onPermissionGranted() {
              //  Toast.makeText(MainActivity.this,"Permissions Granted", Toast.LENGTH_SHORT).show();
            }
            @Override
            public void onPermissionDenied(List<String> deniedPermissions) {
                Toast.makeText(MainActivity.this,"Required Location permission for D2D", Toast.LENGTH_LONG).show();
            }
        };
        TedPermission.with(MainActivity.this)
                .setPermissionListener(permissionListener)
                .setPermissions(perms)
                .check();
    }
    private static String TimeStamp() {
        String currentTime = new SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(new Date());
        return currentTime;
    }

    @RequiresApi(api = Build.VERSION_CODES.O)
    public static String GenerateNonce(){

        SecureRandom rnd = new SecureRandom();
        int byteLength = 32;
        byte[] token = new byte[byteLength];
        rnd.nextBytes(token);
        return convertBytesToHex(token);
    }

    private static String convertBytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte temp : bytes) {
            result.append(String.format("%02x", temp));
        }
        return result.toString();
    }
    public static String GetMacAddress(){ //This will serve as AID
        String stringMac ="";
        try {
            List<NetworkInterface> networkInterfaceList = Collections.list(NetworkInterface.getNetworkInterfaces()); //read in list of network interfaces

            for (NetworkInterface networkInterface:networkInterfaceList){
                if(networkInterface.getName().equalsIgnoreCase("wlan0")){ //compares strings to see if equal, here we are looking for wlan0

                    for(int i=0; i<networkInterface.getHardwareAddress().length;i++){ //access each sub-part of mac address
                        String stringMacByte = Integer.toHexString( networkInterface.getHardwareAddress()[i] & 0xFF); //read back each byte in hex

                        if (stringMacByte.length() == 1){
                            stringMacByte = "0" + stringMacByte; //fill in 0s where length is 1
                        }
                        stringMac =stringMac + stringMacByte.toUpperCase() + ":"; //convert all to uppercase and add semicolons between each 2 hex pair
                    }
                    break;
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return stringMac.substring(0,stringMac.length()-1); //strip last semi colon off
    }

    public KeyPair getKeyPair() { //depreciated since API 24
        KeyPair kp = null;
        SecureRandom Random = new SecureRandom();
        try {
            KeyPairGenerator kpg  = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048,Random); //Key size proportional to message length!
            kp = kpg.generateKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return kp;
    }


    public static String encryptRSAToString(String clearText, String publicKey,boolean FLAG) { //https://stackoverflow.com/questions/12471999/rsa-encryption-decryption-in-android

        String encryptedBase64 = "";
        try {

            KeyFactory keyFac = KeyFactory.getInstance("RSA");

            if(FLAG ==true) {

                KeySpec keySpec = new X509EncodedKeySpec(Base64.decode(publicKey.trim().getBytes(), Base64.DEFAULT)); //take string key and encode
                Key key = keyFac.generatePublic(keySpec);
                final Cipher cipher = getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"); // get an RSA cipher object and print the provider
                cipher.init(ENCRYPT_MODE, key); // encrypt the plain text using the public key
                byte[] encryptedBytes = cipher.doFinal(clearText.getBytes("UTF-8"));
                encryptedBase64 = new String(Base64.encode(encryptedBytes, Base64.DEFAULT));

            }
            else{

                KeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(publicKey.trim().getBytes(), Base64.DEFAULT));
                Key key = keyFac.generatePrivate(keySpec); //Nullor long
                final Cipher cipher = getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING"); // get an RSA cipher object and print the provider
                cipher.init(ENCRYPT_MODE, key);
                byte[] encryptedBytes = cipher.doFinal(clearText.getBytes("UTF-8"));
                encryptedBase64 = new String(Base64.encode(encryptedBytes, Base64.DEFAULT));
            }
        } catch (Exception e) { e.printStackTrace(); }
        return encryptedBase64.replaceAll("(\\r|\\n)", "");
    }

    public static String decryptRSAToString(String encryptedBase64, String privateKey,boolean FLAG){//, boolean FLAG) { //for PGP

        String decryptedString = "";
        try {
            KeyFactory keyFac = KeyFactory.getInstance("RSA");

            if(FLAG == true){
                KeySpec keySpec = new PKCS8EncodedKeySpec(Base64.decode(privateKey.trim().getBytes(), Base64.DEFAULT));
                Key key = keyFac.generatePrivate(keySpec);
                final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
                // encrypt the plain text using the public key
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] encryptedBytes = Base64.decode(encryptedBase64, Base64.DEFAULT);
                byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                decryptedString = new String(decryptedBytes);
            }
            else{ //encode private key like a public key
                KeySpec keySpec = new X509EncodedKeySpec(Base64.decode(privateKey.trim().getBytes(), Base64.DEFAULT));
                Key key = keyFac.generatePublic(keySpec);
                final Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] encryptedBytes = Base64.decode(encryptedBase64, Base64.DEFAULT);
                byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
                decryptedString = new String(decryptedBytes);
            }

        } catch (Exception e) { e.printStackTrace(); }
        return decryptedString;
    }
    private String AESEncryptionMethod(String string){ //AES is symmetric, same key to encrypt and decrypt

        byte[] stringByte = string.getBytes();
        byte[] encryptedByte = new byte[stringByte.length];
        try {
            cipher.init(Cipher.ENCRYPT_MODE,secretKeySpec);
            encryptedByte = cipher.doFinal(stringByte);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        String returnString = null;
        returnString = new String(encryptedByte, StandardCharsets.ISO_8859_1);//specifying what character set to use
        return returnString;
    }

    private String AESDecryptionMethod(String string) {
        String decryptedString = null;
        try {
            byte[] EncryptedByte = string.getBytes(StandardCharsets.ISO_8859_1); //specifying what character set to use (8 bit)
            decryptedString = string;
            byte[] decryption;
            decipher.init(Cipher.DECRYPT_MODE, secretKeySpec); // init decrypt mode with key
            decryption = decipher.doFinal(EncryptedByte); // pass encrypted msg to algorithm
            decryptedString = new String(decryption); //Plaintext

        } catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) { e.printStackTrace(); }
        return decryptedString;
    }


    private String GenerateSignature(String textToSign){
        String SignatureToReturn = null;
        try {
            byte[] tmsg = textToSign.getBytes("UTF-8");
            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initSign(privateKey);
            sig.update(tmsg);
            byte[] signatureBytes = sig.sign();
            SignatureToReturn = new String(Base64.encode(signatureBytes,Base64.DEFAULT));
        } catch (InvalidKeyException e) { e.printStackTrace(); } catch (NoSuchAlgorithmException e) { e.printStackTrace(); } catch (UnsupportedEncodingException e) { e.printStackTrace(); } catch (SignatureException e) { e.printStackTrace(); }
        return SignatureToReturn;
    }

    private boolean VerifySign(String tempMsg) {
        boolean SigState = false;
        try {
            byte[] tmsg = ("HI").getBytes("UTF-8");
            Signature sig = Signature.getInstance("SHA1WithRSA");  //same algorithm
            //Rebuild Key
            KeyFactory keyFac = KeyFactory.getInstance("RSA");
            KeySpec keySpec = new X509EncodedKeySpec(Base64.decode(RecipientKey.trim().getBytes(), Base64.DEFAULT)); //take string key and encode

            RecipientKeyy = keyFac.generatePublic(keySpec);
            sig.initVerify(RecipientKeyy);
            sig.update(tmsg);

            SigState = sig.verify(tempMsg.getBytes("UTF-8")); //Inverse Operation?
            message_history.add(tempMsg + " " + SigState);

            if (SigState) { message_history.add("SIGNATURE VERIFIED"); } else { message_history.add("SIGNATURE NOT VERIFIED"); }

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) { e.printStackTrace(); } catch (InvalidKeyException e) { e.printStackTrace(); } catch (SignatureException e) { e.printStackTrace(); } catch (UnsupportedEncodingException e) { e.printStackTrace(); }

        return SigState;
    }

}



package com.dere.keyattestation;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.os.Environment;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "KeyAttestation";
    private static final String KEY_ALIAS = "attestation_key_v1";
    // Google官方定义的密钥证明扩展标识符
    private static final String KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final int TAG_ROOT_OF_TRUST = 704;
    
    // 文件保存相关配置
    private static final String FILE_NAME = "verified_boot_hash.txt";
    private static final String FAILURE_MESSAGE = "VERIFIED_BOOT_HASH_NOT_FOUND";
    private static final String APP_FOLDER_NAME = "KeyAttestation";

    private TextView tvHash;
    private TextView tvLog;
    private Button btnCopy;
    private String currentHash = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // 初始化界面组件
        tvHash = findViewById(R.id.tv_hash);
        tvLog = findViewById(R.id.tv_log);
        btnCopy = findViewById(R.id.btn_copy);

        // 设置复制按钮功能
        btnCopy.setOnClickListener(v -> {
            if (currentHash != null && !currentHash.isEmpty()) {
                ClipboardManager clipboard = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                ClipData clip = ClipData.newPlainText("VerifiedBootHash", currentHash);
                clipboard.setPrimaryClip(clip);
                Toast.makeText(MainActivity.this, "Hash 值已复制到剪贴板", Toast.LENGTH_SHORT).show();
            } else {
                Toast.makeText(MainActivity.this, "还没有获取到 Hash 值", Toast.LENGTH_SHORT).show();
            }
        });

        btnCopy.setEnabled(false); // 初始状态下禁用复制按钮

        // 在后台线程中执行密钥证明流程
        new Thread(this::performAttestation).start();
    }

    private void performAttestation() {
        try {
            log("正在生成密钥...");

            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            // 如果密钥已存在，先删除旧密钥以确保重新生成证明
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS);
            }

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

            KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    // 设置挑战值以触发完整的证明流程
                    .setAttestationChallenge("hello_world_challenge".getBytes());

            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();
            log("密钥对生成成功");

            Certificate[] certs = keyStore.getCertificateChain(KEY_ALIAS);
            if (certs == null || certs.length == 0) {
                log("错误：无法获取证书链");
                // 将失败状态保存到文件
                saveHashToFile(FAILURE_MESSAGE);
                return;
            }

            X509Certificate leafCert = (X509Certificate) certs[0];
            log("获取到叶子证书，开始解析证书结构...");

            // 从证书扩展中提取验证启动哈希值
            byte[] hashBytes = extractVerifiedBootHash(leafCert);

            if (hashBytes != null) {
                String hexHash = bytesToHex(hashBytes);
                
                // 在主线程中更新界面显示
                runOnUiThread(() -> {
                    currentHash = hexHash;
                    tvHash.setText(hexHash);
                    btnCopy.setEnabled(true);
                    log("\n[成功] 成功获取验证启动哈希值!");
                });
                
                // 将成功的哈希值保存到文件
                saveHashToFile(hexHash);
            } else {
                runOnUiThread(() -> {
                    tvHash.setText("未找到哈希值");
                    log("\n[失败] 未能在证书扩展中找到哈希值");
                });
                
                // 保存失败状态到文件
                saveHashToFile(FAILURE_MESSAGE);
            }

        } catch (Exception e) {
            final String errorMsg = "执行过程中出现异常: " + e.getMessage();
            log(errorMsg);
            e.printStackTrace();
            runOnUiThread(() -> tvHash.setText("处理出错"));
            
            // 保存失败状态到文件
            saveHashToFile(FAILURE_MESSAGE);
        }
    }

    /**
     * 将哈希值保存到公共下载目录的专用文件夹中
     * 只有当新值与文件中现有值不同时才执行写入操作
     */
    private void saveHashToFile(String newHash) {
        try {
            // 使用下载目录下的专用文件夹
            File publicDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            File appFolder = new File(publicDir, APP_FOLDER_NAME);
            File hashFile = new File(appFolder, FILE_NAME);
            
            // 确保目标目录存在
            if (!appFolder.exists()) {
                boolean created = appFolder.mkdirs();
                log("创建应用文件夹: " + created + ", 路径: " + appFolder.getAbsolutePath());
            }
            
            // 读取文件中当前保存的内容
            String currentFileContent = readCurrentFileContent(hashFile);
            
            // 仅当新值与文件内容不同时才进行写入
            if (currentFileContent == null || !currentFileContent.equals(newHash)) {
                try (FileOutputStream fos = new FileOutputStream(hashFile)) {
                    fos.write(newHash.getBytes());
                    log("哈希值已保存到: " + hashFile.getAbsolutePath());
                    log("保存内容: " + newHash);
                    
                    // 同时在应用私有目录保存备份
                    saveToPrivateDirectory(newHash);
                }
            } else {
                log("哈希值与文件现有内容相同，跳过更新");
            }
            
        } catch (Exception e) {
            log("保存到公共目录失败，尝试保存到私有目录: " + e.getMessage());
            // 如果公共目录保存失败，尝试保存到私有目录
            saveToPrivateDirectory(newHash);
        }
    }
    
    /**
     * 在应用私有目录中保存哈希值备份
     */
    private void saveToPrivateDirectory(String newHash) {
        try {
            File filesDir = getFilesDir();
            File privateHashFile = new File(filesDir, FILE_NAME);
            
            try (FileOutputStream fos = new FileOutputStream(privateHashFile)) {
                fos.write(newHash.getBytes());
                log("哈希值已备份到私有目录: " + privateHashFile.getAbsolutePath());
            }
        } catch (Exception e) {
            log("保存到私有目录也失败了: " + e.getMessage());
        }
    }
    
    /**
     * 读取文件当前内容
     */
    private String readCurrentFileContent(File file) {
        if (!file.exists()) {
            return null;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            return content.toString();
        } catch (IOException e) {
            log("读取文件失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 从X509证书的扩展字段中提取验证启动哈希值
     */
    private byte[] extractVerifiedBootHash(X509Certificate cert) throws Exception {
        byte[] extensionValue = cert.getExtensionValue(KEY_ATTESTATION_OID);
        if (extensionValue == null) {
            log("证书缺少密钥证明扩展字段");
            return null;
        }

        ASN1Primitive extensionStruct = toAsn1Primitive(extensionValue);
        if (extensionStruct instanceof ASN1OctetString) {
            extensionStruct = toAsn1Primitive(((ASN1OctetString) extensionStruct).getOctets());
        }

        if (!(extensionStruct instanceof ASN1Sequence)) {
            return null;
        }

        ASN1Sequence attestationRecord = (ASN1Sequence) extensionStruct;
        
        // 证明记录结构说明：
        // 索引6: 软件强制策略列表
        // 索引7: TEE强制策略列表
        
        // 优先在TEE强制列表（索引7）中查找，因为RootOfTrust属于硬件级安全信息
        ASN1Sequence teeEnforced = (ASN1Sequence) attestationRecord.getObjectAt(7);
        ASN1Sequence rootOfTrustSeq = findRootOfTrust(teeEnforced);
        
        // 如果TEE列表中没有找到，尝试在软件列表（索引6）中查找
        if (rootOfTrustSeq == null) {
            log("TEE强制列表中未找到RootOfTrust，尝试在软件列表中查找...");
            ASN1Sequence swEnforced = (ASN1Sequence) attestationRecord.getObjectAt(6);
            rootOfTrustSeq = findRootOfTrust(swEnforced);
        }

        if (rootOfTrustSeq == null) {
            return null;
        }

        // RootOfTrust数据结构：
        // [0] 验证启动密钥
        // [1] 设备锁定状态
        // [2] 验证启动状态
        // [3] 验证启动哈希值（字节字符串）
        if (rootOfTrustSeq.size() >= 4) {
             ASN1Encodable hashObj = rootOfTrustSeq.getObjectAt(3);
             if (hashObj instanceof ASN1OctetString) {
                 return ((ASN1OctetString) hashObj).getOctets();
             }
        }
        return null;
    }

    // 在授权列表中查找标记为704的RootOfTrust序列
    private ASN1Sequence findRootOfTrust(ASN1Sequence authList) {
        Enumeration<?> objects = authList.getObjects();
        while (objects.hasMoreElements()) {
            ASN1Encodable obj = (ASN1Encodable) objects.nextElement();
            if (obj instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) obj;
                if (tagged.getTagNo() == TAG_ROOT_OF_TRUST) {
                    // 修复：使用推荐的getBaseObject().toASN1Primitive()替代已弃用的getObject()
                    ASN1Primitive inner = tagged.getBaseObject().toASN1Primitive();
                    if (inner instanceof ASN1Sequence) {
                        return (ASN1Sequence) inner;
                    }
                }
            }
        }
        return null;
    }

    private ASN1Primitive toAsn1Primitive(byte[] data) throws Exception {
        try (ASN1InputStream input = new ASN1InputStream(data)) {
            return input.readObject();
        }
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> tvLog.append(msg + "\n"));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}                    .setDigests(KeyProperties.DIGEST_SHA256)
                    // 设置挑战值以触发完整的证明流程
                    .setAttestationChallenge("hello_world_challenge".getBytes());

            keyPairGenerator.initialize(builder.build());
            keyPairGenerator.generateKeyPair();
            log("密钥对生成成功");

            Certificate[] certs = keyStore.getCertificateChain(KEY_ALIAS);
            if (certs == null || certs.length == 0) {
                log("错误：无法获取证书链");
                // 将失败状态保存到文件
                saveHashToFile(FAILURE_MESSAGE);
                return;
            }

            X509Certificate leafCert = (X509Certificate) certs[0];
            log("获取到叶子证书，开始解析证书结构...");

            // 从证书扩展中提取验证启动哈希值
            byte[] hashBytes = extractVerifiedBootHash(leafCert);

            if (hashBytes != null) {
                String hexHash = bytesToHex(hashBytes);
                
                // 在主线程中更新界面显示
                runOnUiThread(() -> {
                    currentHash = hexHash;
                    tvHash.setText(hexHash);
                    btnCopy.setEnabled(true);
                    log("\n[成功] 成功获取验证启动哈希值!");
                });
                
                // 将成功的哈希值保存到文件
                saveHashToFile(hexHash);
            } else {
                runOnUiThread(() -> {
                    tvHash.setText("未找到哈希值");
                    log("\n[失败] 未能在证书扩展中找到哈希值");
                });
                
                // 保存失败状态到文件
                saveHashToFile(FAILURE_MESSAGE);
            }

        } catch (Exception e) {
            final String errorMsg = "执行过程中出现异常: " + e.getMessage();
            log(errorMsg);
            e.printStackTrace();
            runOnUiThread(() -> tvHash.setText("处理出错"));
            
            // 保存失败状态到文件
            saveHashToFile(FAILURE_MESSAGE);
        }
    }

    /**
     * 将哈希值保存到公共下载目录的专用文件夹中
     * 只有当新值与文件中现有值不同时才执行写入操作
     */
    private void saveHashToFile(String newHash) {
        try {
            // 使用下载目录下的专用文件夹
            File publicDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
            File appFolder = new File(publicDir, APP_FOLDER_NAME);
            File hashFile = new File(appFolder, FILE_NAME);
            
            // 确保目标目录存在
            if (!appFolder.exists()) {
                boolean created = appFolder.mkdirs();
                log("创建应用文件夹: " + created + ", 路径: " + appFolder.getAbsolutePath());
            }
            
            // 读取文件中当前保存的内容
            String currentFileContent = readCurrentFileContent(hashFile);
            
            // 仅当新值与文件内容不同时才进行写入
            if (currentFileContent == null || !currentFileContent.equals(newHash)) {
                try (FileOutputStream fos = new FileOutputStream(hashFile)) {
                    fos.write(newHash.getBytes());
                    log("哈希值已保存到: " + hashFile.getAbsolutePath());
                    log("保存内容: " + newHash);
                    
                    // 同时在应用私有目录保存备份
                    saveToPrivateDirectory(newHash);
                }
            } else {
                log("哈希值与文件现有内容相同，跳过更新");
            }
            
        } catch (Exception e) {
            log("保存到公共目录失败，尝试保存到私有目录: " + e.getMessage());
            // 如果公共目录保存失败，尝试保存到私有目录
            saveToPrivateDirectory(newHash);
        }
    }
    
    /**
     * 在应用私有目录中保存哈希值备份
     */
    private void saveToPrivateDirectory(String newHash) {
        try {
            File filesDir = getFilesDir();
            File privateHashFile = new File(filesDir, FILE_NAME);
            
            try (FileOutputStream fos = new FileOutputStream(privateHashFile)) {
                fos.write(newHash.getBytes());
                log("哈希值已备份到私有目录: " + privateHashFile.getAbsolutePath());
            }
        } catch (Exception e) {
            log("保存到私有目录也失败了: " + e.getMessage());
        }
    }
    
    /**
     * 读取文件当前内容
     */
    private String readCurrentFileContent(File file) {
        if (!file.exists()) {
            return null;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            return content.toString();
        } catch (IOException e) {
            log("读取文件失败: " + e.getMessage());
            return null;
        }
    }

    /**
     * 从X509证书的扩展字段中提取验证启动哈希值
     */
    private byte[] extractVerifiedBootHash(X509Certificate cert) throws Exception {
        byte[] extensionValue = cert.getExtensionValue(KEY_ATTESTATION_OID);
        if (extensionValue == null) {
            log("证书缺少密钥证明扩展字段");
            return null;
        }

        ASN1Primitive extensionStruct = toAsn1Primitive(extensionValue);
        if (extensionStruct instanceof ASN1OctetString) {
            extensionStruct = toAsn1Primitive(((ASN1OctetString) extensionStruct).getOctets());
        }

        if (!(extensionStruct instanceof ASN1Sequence)) {
            return null;
        }

        ASN1Sequence attestationRecord = (ASN1Sequence) extensionStruct;
        
        // 证明记录结构说明：
        // 索引6: 软件强制策略列表
        // 索引7: TEE强制策略列表
        
        // 优先在TEE强制列表（索引7）中查找，因为RootOfTrust属于硬件级安全信息
        ASN1Sequence teeEnforced = (ASN1Sequence) attestationRecord.getObjectAt(7);
        ASN1Sequence rootOfTrustSeq = findRootOfTrust(teeEnforced);
        
        // 如果TEE列表中没有找到，尝试在软件列表（索引6）中查找
        if (rootOfTrustSeq == null) {
            log("TEE强制列表中未找到RootOfTrust，尝试在软件列表中查找...");
            ASN1Sequence swEnforced = (ASN1Sequence) attestationRecord.getObjectAt(6);
            rootOfTrustSeq = findRootOfTrust(swEnforced);
        }

        if (rootOfTrustSeq == null) {
            return null;
        }

        // RootOfTrust数据结构：
        // [0] 验证启动密钥
        // [1] 设备锁定状态
        // [2] 验证启动状态
        // [3] 验证启动哈希值（字节字符串）
        if (rootOfTrustSeq.size() >= 4) {
             ASN1Encodable hashObj = rootOfTrustSeq.getObjectAt(3);
             if (hashObj instanceof ASN1OctetString) {
                 return ((ASN1OctetString) hashObj).getOctets();
             }
        }
        return null;
    }

    // 在授权列表中查找标记为704的RootOfTrust序列
    private ASN1Sequence findRootOfTrust(ASN1Sequence authList) {
        Enumeration<?> objects = authList.getObjects();
        while (objects.hasMoreElements()) {
            ASN1Encodable obj = (ASN1Encodable) objects.nextElement();
            if (obj instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) obj;
                if (tagged.getTagNo() == TAG_ROOT_OF_TRUST) {
                    // 修复：使用推荐的getBaseObject().toASN1Primitive()替代已弃用的getObject()
                    ASN1Primitive inner = tagged.getBaseObject().toASN1Primitive();
                    if (inner instanceof ASN1Sequence) {
                        return (ASN1Sequence) inner;
                    }
                }
            }
        }
        return null;
    }

    private ASN1Primitive toAsn1Primitive(byte[] data) throws Exception {
        try (ASN1InputStream input = new ASN1InputStream(data)) {
            return input.readObject();
        }
    }

    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> tvLog.append(msg + "\n"));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

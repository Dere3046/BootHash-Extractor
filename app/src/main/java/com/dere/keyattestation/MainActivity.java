package com.dere.keyattestation;

import android.Manifest;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Log;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "KeyAttestation";
    private static final String KEY_ALIAS = "attestation_key_v1";
    // 这是Google官方定义的密钥证明扩展标识符
    private static final String KEY_ATTESTATION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final int TAG_ROOT_OF_TRUST = 704;
    
    // 文件保存相关配置
    private static final String FILE_NAME = "verified_boot_hash.txt";
    private static final String FAILURE_MESSAGE = "VERIFIED_BOOT_HASH_NOT_FOUND";
    private static final String APP_FOLDER_NAME = "KeyAttestation";
    
    // 权限请求代码
    private static final int PERMISSION_REQUEST_CODE = 1001;
    private static final int MANAGE_STORAGE_REQUEST_CODE = 1002;

    private TextView tvHash;
    private TextView tvLog;
    private Button btnCopy;
    private String currentHash = null;
    
    // 记录是否有存储权限
    private boolean hasStoragePermission = false;

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

        // 检查并请求必要的权限
        checkAndRequestPermissions();
    }

    /**
     * 检查并请求存储权限
     * 根据Android版本使用不同的权限请求方式
     */
    private void checkAndRequestPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // Android 11 (API 30) 及以上版本需要使用新的存储权限管理
            if (Environment.isExternalStorageManager()) {
                hasStoragePermission = true;
                startAttestationProcess();
            } else {
                showManageStoragePermissionDialog();
            }
        } else {
            // Android 10 (API 29) 及以下版本使用传统的存储权限
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    == PackageManager.PERMISSION_GRANTED) {
                hasStoragePermission = true;
                startAttestationProcess();
            } else {
                ActivityCompat.requestPermissions(this,
                        new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
                        PERMISSION_REQUEST_CODE);
            }
        }
    }

    /**
     * 显示存储权限请求对话框
     * 向用户解释为什么需要这个权限
     */
    private void showManageStoragePermissionDialog() {
        new AlertDialog.Builder(this)
                .setTitle("存储权限请求")
                .setMessage("应用需要存储权限来保存验证启动哈希值文件。请授予\"所有文件访问权限\"。")
                .setPositiveButton("去设置", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        requestManageStoragePermission();
                    }
                })
                .setNegativeButton("取消", new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        log("用户拒绝授予存储权限");
                        // 即使没有权限也继续执行，但只能保存到私有目录
                        startAttestationProcess();
                    }
                })
                .setCancelable(false)
                .show();
    }

    /**
     * 请求管理所有文件的权限 (Android 11+)
     * 这会跳转到系统设置页面让用户授权
     */
    private void requestManageStoragePermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            try {
                Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                intent.setData(Uri.parse("package:" + getPackageName()));
                startActivityForResult(intent, MANAGE_STORAGE_REQUEST_CODE);
            } catch (Exception e) {
                log("打开设置页面失败: " + e.getMessage());
                // 即使设置页面打开失败也继续执行
                startAttestationProcess();
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == MANAGE_STORAGE_REQUEST_CODE) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                if (Environment.isExternalStorageManager()) {
                    hasStoragePermission = true;
                    log("已获得所有文件访问权限");
                } else {
                    log("用户拒绝授予所有文件访问权限");
                }
            }
            startAttestationProcess();
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, 
                                         @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                hasStoragePermission = true;
                log("已获得存储权限");
            } else {
                log("用户拒绝授予存储权限");
            }
            startAttestationProcess();
        }
    }

    /**
     * 开始密钥证明流程
     * 这是应用的主要功能
     */
    private void startAttestationProcess() {
        if (!hasStoragePermission) {
            log("注意: 没有存储权限，文件将只能保存到私有目录");
        }
        
        // 在后台线程中执行密钥证明流程，避免阻塞UI
        new Thread(this::performAttestation).start();
    }

    /**
     * 执行密钥证明的主要逻辑
     * 包括生成密钥、获取证书、解析验证启动哈希等步骤
     */
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
     * 将哈希值保存到文件
     * 这个方法会同时尝试保存到私有目录和公有目录，两个操作完全独立
     * 即使一个保存失败，另一个也不会受到影响
     */
    private void saveHashToFile(String newHash) {
        // 同时保存到两个目录，互不影响
        saveToPrivateDirectory(newHash);  // 保存到应用私有目录
        saveToPublicDirectory(newHash);   // 尝试保存到公共目录
    }
    
    /**
     * 保存哈希值到应用私有目录
     * 这个操作不需要任何权限，总是会尝试执行
     * 即使失败也不会影响公有目录的保存
     */
    private void saveToPrivateDirectory(String newHash) {
        new Thread(() -> {
            try {
                File filesDir = getFilesDir();
                File privateHashFile = new File(filesDir, FILE_NAME);
                
                // 写入文件，覆盖任何现有内容
                try (FileOutputStream fos = new FileOutputStream(privateHashFile, false)) {
                    fos.write(newHash.getBytes());
                    log("[私有目录] 保存成功: " + privateHashFile.getAbsolutePath());
                    log("[私有目录] 保存内容: " + newHash);
                }
            } catch (Exception e) {
                log("[私有目录] 保存失败: " + e.getMessage());
                // 这里捕获异常但不重新抛出，确保不影响公有目录保存
            }
        }).start();
    }
    
    /**
     * 尝试保存哈希值到公共下载目录
     * 这个操作需要存储权限，如果没有权限会跳过
     * 即使失败也不会影响私有目录的保存
     */
    private void saveToPublicDirectory(String newHash) {
        new Thread(() -> {
            // 先检查是否有存储权限
            if (!hasStoragePermission) {
                log("[公有目录] 没有存储权限，跳过保存");
                return;
            }
            
            try {
                // 使用下载目录下的专用文件夹
                File publicDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
                File appFolder = new File(publicDir, APP_FOLDER_NAME);
                File hashFile = new File(appFolder, FILE_NAME);
                
                // 确保目标目录存在
                if (!appFolder.exists()) {
                    boolean created = appFolder.mkdirs();
                    if (!created) {
                        log("[公有目录] 无法创建应用文件夹: " + appFolder.getAbsolutePath());
                        return; // 目录创建失败，直接返回
                    }
                }
                
                // 写入文件，覆盖任何现有内容
                try (FileOutputStream fos = new FileOutputStream(hashFile, false)) {
                    fos.write(newHash.getBytes());
                    log("[公有目录] 保存成功: " + hashFile.getAbsolutePath());
                    log("[公有目录] 保存内容: " + newHash);
                }
                
            } catch (Exception e) {
                log("[公有目录] 保存失败: " + e.getMessage());
                // 这里捕获异常但不重新抛出，确保不影响私有目录保存
            }
        }).start();
    }

    /**
     * 从X509证书的扩展字段中提取验证启动哈希值
     * 这是整个应用的核心功能
     */
    private byte[] extractVerifiedBootHash(X509Certificate cert) throws Exception {
        byte[] extensionValue = cert.getExtensionValue(KEY_ATTESTATION_OID);
        if (extensionValue == null) {
            log("证书缺少密钥证明扩展字段");
            return null;
        }

        // 解析ASN.1结构
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
        
        // 优先在TEE强制列表（索引7）中查找，因为RootOfTrust通常属于硬件级安全信息
        ASN1Sequence teeEnforced = (ASN1Sequence) attestationRecord.getObjectAt(7);
        ASN1Sequence rootOfTrustSeq = findRootOfTrust(teeEnforced);
        
        // 如果TEE列表中没有找到，尝试在软件列表中查找
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

    /**
     * 在授权列表中查找标记为704的RootOfTrust序列
     * 704是Google定义的RootOfTrust标签号
     */
    private ASN1Sequence findRootOfTrust(ASN1Sequence authList) {
        Enumeration<?> objects = authList.getObjects();
        while (objects.hasMoreElements()) {
            ASN1Encodable obj = (ASN1Encodable) objects.nextElement();
            if (obj instanceof ASN1TaggedObject) {
                ASN1TaggedObject tagged = (ASN1TaggedObject) obj;
                if (tagged.getTagNo() == TAG_ROOT_OF_TRUST) {
                    // 使用推荐的方法获取内部对象
                    ASN1Primitive inner = tagged.getBaseObject().toASN1Primitive();
                    if (inner instanceof ASN1Sequence) {
                        return (ASN1Sequence) inner;
                    }
                }
            }
        }
        return null;
    }

    /**
     * 将字节数组转换为ASN.1原始对象
     * 用于解析证书扩展字段
     */
    private ASN1Primitive toAsn1Primitive(byte[] data) throws Exception {
        try (ASN1InputStream input = new ASN1InputStream(data)) {
            return input.readObject();
        }
    }

    /**
     * 记录日志信息
     * 同时输出到Logcat和界面上的日志文本框
     */
    private void log(String msg) {
        Log.d(TAG, msg);
        runOnUiThread(() -> tvLog.append(msg + "\n"));
    }

    /**
     * 将字节数组转换为十六进制字符串
     * 用于显示哈希值
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}

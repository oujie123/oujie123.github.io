package test;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.SSLContext;

import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContexts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

public class GACPemTlsDemo {
	private static String VEHICLE_CRT_PATH = "D:\\gac_xinghe\\vehicleCA.crt";
	private static String VEHICLE_KEY_PATH = "D:\\gac_xinghe\\vehicleCA.key";
	private static String VEHICLE_KEY_PWD = "53A070BD720A2D9ED38EDA72C3EBE854A2AEE92B";
	private static String ROOT_CRT_PATH = "D:\\gac_xinghe\\rootCA.crt";
	
	private static String API_URL = "https://xx.xx.com";
	

	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, KeyManagementException, UnrecoverableKeyException, InvalidKeyException, InvalidKeySpecException {
		System.setProperty("javax.net.debug", "ssl");//输出SSL通讯信息
		/* 读取证书证书 */
		String vehicleCrt = readVehicleStr(VEHICLE_CRT_PATH);
		Map<String, String> rootMap = readRootCA(ROOT_CRT_PATH);
		String root1 = rootMap.get("root1");
		String root2 = rootMap.get("root2");
		
		/*构造客户端证书的KeyStore*/
	    char[] pwd = "123456".toCharArray();	//构造keyStore对象，需要设定的密码，该密码可以任意设置
	    
	    Provider bcProvider = new BouncyCastleProvider();
	    Security.addProvider(new BouncyCastleProvider());
	    
	    CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

	    //构造客户端证书的KeyStore对象
	    KeyStore clientCertKeyStore = KeyStore.getInstance("BKS", bcProvider);
	    clientCertKeyStore.load(null, pwd);
        //读取车端证书,公钥
	    ByteArrayInputStream bais = new ByteArrayInputStream(Base64.decodeBase64(vehicleCrt));
	    X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(bais);
	    
        //定义车端证书alias
        String keyAlias = "vehicleCA";
		
        KeyPair keyPair = getKey(VEHICLE_KEY_PWD, VEHICLE_KEY_PATH);
        
        Certificate[] certificates = new Certificate[]{x509Certificate};
        clientCertKeyStore.setKeyEntry(keyAlias, keyPair.getPrivate(), pwd, certificates);
        
	    //构造可信服务端证书的KeyStore对象
	    KeyStore trustKeyStore = KeyStore.getInstance("BKS", bcProvider);
	    trustKeyStore.load(null, pwd);
	    //读取根证书
	    ByteArrayInputStream trust1Bais = new ByteArrayInputStream(Base64.decodeBase64(root1));
	    X509Certificate trust1X509Certificate = (X509Certificate) certificateFactory.generateCertificate(trust1Bais);
	    trustKeyStore.setCertificateEntry("root1", trust1X509Certificate);
	    
	    ByteArrayInputStream trust2Bais = new ByteArrayInputStream(Base64.decodeBase64(root2));
	    X509Certificate trust2X509Certificate = (X509Certificate) certificateFactory.generateCertificate(trust2Bais);
	    trustKeyStore.setCertificateEntry("root2", trust2X509Certificate);
        
        SSLContext sslcontext = SSLContexts.custom()
        		.loadTrustMaterial(trustKeyStore, new TrustStrategy(){
        			public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        				return true;
        			}})
        		.loadKeyMaterial(clientCertKeyStore, pwd)
        		.build();
        
        SSLConnectionSocketFactory sslConnectionSocketFactory  = new SSLConnectionSocketFactory(
                sslcontext,
                new String[] {"TLSv1", "TLSv1.1", "TLSv1.2"},// 协议
                null,
                SSLConnectionSocketFactory.getDefaultHostnameVerifier());
        
        CloseableHttpClient httpClient = HttpClients.custom()
        		.setSSLSocketFactory(sslConnectionSocketFactory)
        		.build();

		List<NameValuePair> parameters = new ArrayList<NameValuePair>();
	
		HttpPost httpPost = new HttpPost(API_URL);
		httpPost.setEntity(new UrlEncodedFormEntity(parameters,Charset.forName("UTF-8")));
		
		httpPost.setHeader("Content-AppKey", ""); 
		httpPost.setHeader("Content-Signature","" );
		httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");
		CloseableHttpResponse response = httpClient.execute(httpPost);
		
		int status = response.getStatusLine().getStatusCode();
		System.out.println("通讯返回状态码："+status);
		
		HttpEntity entity = response.getEntity();
		
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		
		copy(entity.getContent(),outputStream);
		
		String respStr = new String(outputStream.toByteArray(), "UTF-8");
		
		System.out.println("返回结果："+respStr);
	}
	
	public static long copy(InputStream input, OutputStream output) throws IOException {
		byte[] buffer = new byte[1024 * 4];
		long count = 0;
		int n = 0;
		while (-1 != (n = input.read(buffer))) {
			output.write(buffer, 0, n);
			count += n;
		}
		return count;
	}
	public static KeyPair getKey(String keyPWD,String keyFile) {
		 Security.addProvider(new BouncyCastleProvider());
		 try {
			 File privateKeyFile = new File(keyFile); // private key file in PEM format
			 PEMParser pemParser = new PEMParser(new FileReader(privateKeyFile));
		     Object object = pemParser.readObject();
		     PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(keyPWD.toCharArray());
		     JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
		     if (object instanceof PEMEncryptedKeyPair) {
		    	 return converter.getKeyPair(((PEMEncryptedKeyPair) object).decryptKeyPair(decProv));
		     } else {
		    	 return converter.getKeyPair((PEMKeyPair) object);
		     }
		     
		 } catch (Exception e) {
			 throw new RuntimeException(e);
		 }
	}
	public static String readVehicleStr(String filePath) {
		String pemStr = "";
        try {
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(filePath), "UTF-8"));
            String lineStr = null;
            while((lineStr=bufferedReader.readLine())!=null){
            	if(lineStr.length()== 0 || lineStr.indexOf(": ")>=0 || lineStr.indexOf("-----BEGIN")>=0 || lineStr.indexOf("-----END")>=0 ) {
            		continue;
            	}
            	pemStr+= lineStr.replace("\t", "");
            }
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}

		return pemStr;
	}
	
	public static Map<String, String> readRootCA(String filePath) {
		Map<String, String>  retMap = new HashMap<String, String>();
		String root1Str = "";
		String root2Str = "";
		int bolCount = 0;
        try {
			BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(filePath), "UTF-8"));
            String lineStr = null;
            while((lineStr=bufferedReader.readLine())!=null){
            	if(lineStr.length()== 0 ) {
            		continue;
            	}
            	if(lineStr.indexOf("-----BEGIN")>=0) {
            		bolCount ++ ;
            		continue;
            	}
            	if(lineStr.indexOf("-----END")>=0 ) {
            		continue;
            	}
            	
            	if(bolCount<=1) {
            		root1Str+= lineStr.replace("\t", "");
            	}else {
            		root2Str+= lineStr.replace("\t", "");
            	}
            }
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
        
        retMap.put("root1", root1Str);
        retMap.put("root2", root2Str);

		return retMap;
	}
}

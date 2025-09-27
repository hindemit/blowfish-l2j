# Blowfish-L2J

[![Maven Central](https://img.shields.io/maven-central/v/io.github.hindemit/blowfish-l2j)](https://mvnrepository.com/artifact/io.github.hindemit/blowfish-l2j)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A lightweight **Blowfish cipher engine** implementation tailored for Lineage II (L2J) projects.  
This library provides a clean, extensible API for encryption and decryption using the Blowfish block cipher.

---

## ✨ Features

- Pure Java implementation of the Blowfish algorithm
- Simple `CipherEngine` interface for easy integration
- Support for encryption and decryption with the same key
- Lightweight, no external dependencies
- Available from **Maven Central**

---

## 📦 Installation

Add the dependency to your project:

### Maven
```xml
<dependency>
    <groupId>io.github.hindemit</groupId>
    <artifactId>blowfish-l2j</artifactId>
    <version>0.0.1</version>
</dependency>
```

### Gradle (Kotlin DSL)
``` kotlin
implementation("io.github.hindemit:blowfish-l2j:0.0.1")
```

### Gradle (Groovy)
```groovy
implementation 'io.github.hindemit:blowfish-l2j:0.0.1'
```

## 🚀 Usage
```java
import io.github.hindemit.crypt.BlowfishEngine;
import io.github.hindemit.crypt.CipherEngine;

public class Example {
    public static void main(String[] args) {
        byte[] key = "MySecretKey".getBytes();

        CipherEngine encryptEngine = new BlowfishEngine();
        encryptEngine.init(true, key);

        CipherEngine decryptEngine = new BlowfishEngine();
        decryptEngine.init(false, key);

        byte[] plain = "HelloWorld".getBytes();

        // Ensure input is padded to a multiple of 8 bytes
        byte[] padded = java.util.Arrays.copyOf(plain, 16);

        byte[] encrypted = new byte[padded.length];
        encryptEngine.processBlock(padded, 0, encrypted, 0);

        byte[] decrypted = new byte[encrypted.length];
        decryptEngine.processBlock(encrypted, 0, decrypted, 0);

        System.out.println("Decrypted: " + new String(decrypted).trim());
    }
}
```

## 🛠 Development
Clone the repository and build locally:
```bash
git clone https://github.com/hindemit/blowfish-l2j.git
cd blowfish-l2j
mvn clean install
```
The library will be installed in your local Maven repository (`~/.m2/repository`).

## 🤝 Contributing
Contributions, [issues](https://github.com/hindemit/blowfish-l2j/issues), and feature requests are welcome!
Feel free to open an issue.

# libts

A C/C++ cross-platform/cross-language library for validating RFC3161 timestamp signature

# 编译openssl

如果你要自己编译openssl，可以参考以下内容

理论上，本项目依赖openssl只需要ts模块

所以我参考https://github.com/openssl/openssl/blob/master/INSTALL.md#enable-and-disable-features 移除了一些不必要的功能

编译后的openssl文件夹仅157MB大（原先有6GB多）

我对openssl不了解，可能移除错导致程序出错或性能损失，不过目前没有测试出来

openssl编译选项：

```shell
no-filenames no-shared no-apps no-autoload-config no-tests no-deprecated no-docs no-legacy no-sock no-srp no-srtp no-psk no-ui-console no-quic no-dgram no-http no-ssl no-ssl3 no-tls no-dtls no-engine no-comp no-ec no-ec2m no-dynamic-engine no-ocsp no-cms
```

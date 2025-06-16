## 语言调用流程
`main.go`
- main()：`notaryCommander := &notaryCommander{getRetriever: getPassphraseRetriever}` 初始化notaryCommander
	- notaryCommander：包含一个PassRetriever成员 `getRetriever func() notary.PassRetriever`
	- getPassphraseRetriever()：获得PassRetriever
- `PassRetriever.go`：PassRetriever模块代码
`tuf.go`
- ConfigureRepo()：把notaryCommander中的getRetriever成员用以初始化Repository
`CryptoService.go`
- AddKey()：调用KeyStorage的AddKey
`Keystorage.go`
- AddKey()：GenericKeyStore的AddKey调用passRetriever
```go
for attempts := 0; ; attempts++ {
	chosenPassphrase, giveup, err = s.PassRetriever(keyID, keyInfo.Role.String(), true, attempts)
	
	if err == nil {
		break
	}
	
	if giveup || attempts > 10 {
		return ErrAttemptsExceeded{}
	}
}
```
## Cpp调用流程
创建与赋值：
- `main.cpp`：notary命令（以init为例）的回调函数中调用Repository构造函数
```cpp
init->callback([&]() {
	// ...
	// 2. 创建仓库工厂并获取仓库实例
	Repository repo(gun, trustDir, serverURL);
	// ...
}        
```
- `repository.cpp`：`Repository`类的构造函数添加passRetriever
```cpp
Repository::Repository(const GUN& gun, const std::string& trustDir, const std::string& serverURL)
    {
    //...
    auto passRetriever = passphrase::PromptRetriever();
    //...
```
- `PassRetriever.cpp`：实现具体功能
调用：
- `crypto_service.cpp`：AddKey()：调用KeyStorage的AddKey
- `key_storage.go`：GenericKeyStore的AddKey调用passRetriever
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

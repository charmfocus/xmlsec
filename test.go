package xmlsec

import (
	"fmt"
	"io/ioutil"
	"os"
)

var privateKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAzS4nzBr5qR+FfdIk6DgAkuER6RJ64sEL0exAGKVQv/XFvGgk
f5nxNivzrm4ZSkeIwVTX9jxI6iefNDmVtMafPRTMcL8fGj4WIgtloreGjKHeMLJy
eR38JihBGqUGrolBQpZBxu9e3GpUzYGUQ6i2q2bVFXjtbDz236aoy9sznZ1kwlsm
RcNdVqGtTOvBnaSbrfgM0wObBdChGRgOLx+u80iowiIn27+Nr9+UU4SlVjh/osIl
LbFpGuufsKBWZ7u7eIWcOsC3gCLhORPzvFmYrMBHImWnIeje/mgcdtfdjjQgSdqi
YX6h/V/BG9XupMlJb0SpxHyBOaiYKsFAdBe4bwIDAQABAoIBAQCc4dOwLlgCxoVN
ZSavIFLf+5O0QFsRkkW1ZwzDS3PossVUf9SYdF6I6yZRkwFnWDbqjDLspb+iulTy
m60qIkyTaZnAA4KGkD5gHZLCzczlLsczON5qWVD45AKTmub3AR+TCEyXDWPc6Lia
wZ9Z9GBnwiLfXi07e4nQDCA4bwyST+070fpyz6cJUPo7dEFU71Kh/r9+m7srZ1JL
wsjiTnk5C8vyraRiDxg+jSyUKPLFYjmYd/XrkYvk11CbuktkM6TTsyDya4Aw38wf
znCHlLCnbI6Cicd3qgr6AXtbeLaXHfaaS/gQuQ2jWmwh0q54u91c6qS/S7BJeEnG
v6oCtUTxAoGBAPJGJOc2L8ndHl4abb84QSShcMRN0gdf8oKSDQQ8oNFpfO5/BxTK
7VqpMnYdn+y6gogX7Qo/UywAcFCMJOQT+ZLcWna+S7fMu5TCN3rlw7Z7dmG4uL+u
XzChm0QG5oS53rvHzNoSAPz7od/sqet+SXes6pN+Dssanz+MZzgf/NGFAoGBANjO
BHR5WQUuNbBsynkoj27ouB2MdleAdXPWmfftnWhwDXuDj1rLUv1YU9JBwiaG0jQE
KvNpgy2CcFQAL1naiu18DhrcvASIIeLOk2UEIQOsvaP8Al+nMJyYDzjDYPFD96X1
y4Ud1pDYdm5eZKWCgaCb4gXLaEm88gNg8n6YLYpjAoGAEHgSNCFr2DYOxWjYgwIo
83uB9eYwW83650NUXTBd4j5gfrnl2lT9E4ei5YKYB3iaPPQbafHqDnitKdyM+XAe
LAyMnbvL29+v9KnLKbCKwFHeN0BeVrFcySqDKnmpm+YirPMlCsHkjU3xsA4fcuGv
ztHTVFliWg4iOyipL5iFEB0CgYEA0yvHlxNjK/KYhOFSTbS+EI9IVi+sTQpoXI4Y
pi6hdUo/N6ErDoqgqPdRnahDTXdgYx30H+cTyE4WzxrnBCQj0bFVo8CAugFG0D3Z
vzjIV2X3yTP7s+OLK9vIZ8eWMym6m8HPnDc1+Rt+L35tlfCKBkAPZQl86OXK7JOP
XtMm+HUCgYBl0heVYs5jayK27ryNfNsTu2M01lbyjU6xbXqrsI/ny667Zfm8N57r
PS45GDXSj1T2fkrHoeqFeBaRZYxH0jAdCRNzZZangWe0/3gQpsZRDYsLs4OzjyYW
SCjACGz1ol5DsCHkFnylV/HTHpVdXPLU5vwij1CjUzXii2OfcjZ/LA==
-----END RSA PRIVATE KEY-----`)

var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDOb4B1dnwONcW0RoJMa0IOq3O6jiqnTGLUpxEw
2xJg+c7wsb6DBy5CAoR0w2ZjZ/BjKxGIQ+DoDg3NsHJeyuEjNF0/Ro/R5xVpFC5z4cBVSC2/gddz
4a1EoGDJewML/Iv0yIw7ylB86++h23nRd079c5S9RZXurBfnLW2Srhqk2QIDAQAB
-----END PUBLIC KEY-----`)

func TestSign() {
	f, _ := os.Open("request.xml")
	s, _ := ioutil.ReadAll(f)
	value, err := Sign(s, privateKey)
	fmt.Println(string(value), err)
}

func TestVerifySign() {
	f, _ := os.Open("response.xml")
	s, _ := ioutil.ReadAll(f)
	ok, err := VerifySign(s, publicKey)
	fmt.Println(ok, err)
}

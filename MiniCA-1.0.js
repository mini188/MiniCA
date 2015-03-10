/**
* @Author mini188 2013 mini188 Co., Ltd.
* @Version 1.0
* 本单元主要是提供对数字证书、加密算法、数字签名的js支持，基于微软的CAPICOM组件进行了封装
* 只能应用于windows环境下，支持IE6及以上版本
**/
var CAPICOM_CURRENT_USER_STORE = 2;
var CAPICOM_ENCODE_BASE64 = 0;
var CAPICOM_INFO_SUBJECT_SIMPLE_NAME = 0;
var CAPICOM_INFO_ISSUER_SIMPLE_NAME = 1;
//var CAPICOM_INFO_SUBJECT_EMAIL_NAME = 2;
//var CAPICOM_INFO_ISSUER_EMAIL_NAME  = 3;

var CAPICOM_CERTIFICATE_FIND_ISSUER_NAME = 2;
var CAPICOM_STORE_OPEN_READ_ONLY = 0

//var CAPICOM_KEY_SPEC_KEYEXCHANGE= 1
//var CAPICOM_KEY_SPEC_SIGNATURE = 2 	

var CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME = 0;
var CAPICOM_E_CANCELLED = -2138568446;
var CAPICOM_VERIFY_SIGNATURE_ONLY = 0;
var CAPICOM_VERIFY_SIGNATURE_AND_CERTIFICATE = 1;

var CAPICOM_CERTIFICATE_FIND_TIME_VALID = 9;
var CAPICOM_CERTIFICATE_FIND_SHA1_HASH = 0;
var CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY = 6;
var CERT_KEY_SPEC_PROP_ID = 6;
var CAPICOM_CERTIFICATE_FIND_KEY_USAGE = 12;
var CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE = 0x00000080;
var CAPICOM_DATA_ENCIPHERMENT_KEY_USAGE = 16;
var CAPICOM_HASH_ALGORITHM_SHA1 = 0;
var CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT = 0;

// 命名空间申明
this.Mini = this.Mini || {};
Mini.Digital = {};

/*
*  数字证书类，封装了证书的方法及属性
*  作者：mini188
*/
Mini.Digital.Certificate = function (inputCert) {
    var _currCert = inputCert;

    //this.LoadFrom

    /*
    * 将证书转换为base64编码
    * @return 返回证书的Base64编码信息
    */
    this.TransCertToBase64 = function () {
        if (!_currCert) {
            throw "证书对象_currCert不存在。";
        }
        return _currCert.Export(CAPICOM_ENCODE_BASE64);
    }

    this.GetIssuerName = function () {
        return _currCert.IssuerName;
    }

    this.GetSerialNumber = function () {
        return _currCert.SerialNumber;
    }

    this.GetSubjectName = function () {
        return _currCert.SubjectName;
    }

    this.GetThumbprint = function () {
        return _currCert.Thumbprint;
    }
}


/*
*  数字证书存储空间类，封装了证书Store
*  作者：mini188
*/
Mini.Digital.Store = function () {
    var _issued;
    var _storename;
    var _store = new ActiveXObject("CAPICOM.Store");
    var _isopend = false;

    //打开store
    function _openstore(storename) {
        _storename = storename;
        try {
            if (!_store) {
                _store = new ActiveXObject("CAPICOM.Store")
            }
            _store.Open(CAPICOM_CURRENT_USER_STORE, _storename, CAPICOM_STORE_OPEN_READ_ONLY);
            _isopend = true;
        }
        catch (e) {
            if (e.number != CAPICOM_E_CANCELLED) {
                throw "选择的证书有问题，请确认USBkey是否正确插入!";
            }
        }
    }

    /*
    * 打开store
    */
    this.OpenStore = function (storename, issued) {
        _issued = issued;
        _openstore(storename);
    }

    /*
    * 关闭store
    */
    this.CloseStore = function () {
        if (_isopend) {
            _store.Close();
            _store = null;
        }
    }

    /*
    * 获取StroeName
    */
    this.GetStoreName = function () {
        return _storename;
    }


    //获取证书
    this.GetCert = function () {
        var certificates = this.GetCertList();

        if (!certificates || (certificates.Count == 0)) {
            return null;
        }
        else {
            var selectedCertificate = new ActiveXObject("CAPICOM.Certificate");
            try {
                selectedCertificate = certificates.Select();
            }
            catch (e) {
                if (e.number = CAPICOM_E_CANCELLED) {
                    return null;
                }
                throw e;
            }
            return selectedCertificate.Item(1);
        }
    }

    //获取证书列表
    this.GetCertList = function () {
        if (_isopend == false) {
            throw "还未打开任何证书空间";
        }

        var certificates = _store.Certificates.Find(CAPICOM_CERTIFICATE_FIND_KEY_USAGE, CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE)
        .Find(CAPICOM_CERTIFICATE_FIND_TIME_VALID)
        .Find(CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY, CERT_KEY_SPEC_PROP_ID)
        .find(CAPICOM_CERTIFICATE_FIND_ISSUER_NAME, _issued);

        if (certificates.Count == 0) {
            return null;
        }
        else {
            return certificates;
        }
    }

    /*
    * 通过Hash值查找证书
    * @param hash 证书hash值
    * @return 返回查找到的证书信息，如果未查找到返回null
    */
    this.FindCertByHash = function (hash) {
        if (_isopend == false) {
            throw "还未打开任何证书空间";
        }

        var filteredCertificates = _store.Certificates.Find(CAPICOM_CERTIFICATE_FIND_SHA1_HASH, hash);
        if (filteredCertificates.Count > 0) {
            return filteredCertificates.Item(1);
        }
        else {
            return null;
        }
    }
}

/*
* 数字签名
* 作者：mini188
*/
Mini.Digital.Signer = function () {
    var _signer = new ActiveXObject("CAPICOM.Signer"); //签名者对象
    var _signedData = new ActiveXObject("CAPICOM.SignedData");

    /*
    * 从指定pfx证书文件中加载签名证书
    */
    function _loadFormFile(pfxFile) {
        try {
            _signer.Load(pfxFile);
            return true;
        }
        catch (e) {
            return false;
        }
    }

    /*
    * 使用指定证书文件对文本进行签名
    * @param pfxFile 签名用的证书文件
    * @param content 待签名的文本内容
    * @return 签名正确返回签名的字符串，失败返回null
    */
    this.SignTextByPfxFile = function (pfxFile, content) {
        try {
            _signedData.Content = content;
            if (_loadFormFile(pfxFile) == false) {
                throw "加载证书文件失败。";
            }

            var szSignature = _signedData.Sign(_signer, false, CAPICOM_ENCODE_BASE64);
            return szSignature;
        }
        catch (e) {
            return null;
        }
    }

    /*
    * 对文本进行签名
    * @param cert 签名用的证书
    * @param content 待签名的文本内容
    * @return 签名正确返回签名的字符串，失败返回null
    */
    this.SignText = function (cert, content) {
        try {
            _signedData.Content = content;
            _signer.Certificate = cert;

            var szSignature = _signedData.Sign(_signer, false, CAPICOM_ENCODE_BASE64);
            return szSignature;
        }
        catch (e) {
            return null;
        }
    }

    /*
    * 验证签名
    * @param hash 哈希值
    * @param signcontent 签名串
    * @return 验证成功返回true，否则返回false
    */
    this.VerifySign = function (hash, signcontent) {
        try {
            _signedData.Content = hash;
            _signedData.Verify(signcontent, false, CAPICOM_VERIFY_SIGNATURE_ONLY);
            return true;
        }
        catch (e) {
            return false;
        }
    }
}

/*
* 加密和解密，支持对称和非对称的实现
* 作者：mini188
*/
Mini.Digital.Encrypted = function () {
    var _encryption = new ActiveXObject("CAPICOM.EnvelopedData"); //envelop data for privacy by encryption

    /*
    * 加密
    * @param cert 用于加密的证书
    * @param plaintext 明文
    */
    function _encrypt(cert, plaintext) {
        if (!cert) {
            throw "传入的数字证书不能为空";
        }
        if (plaintext == "") {
            throw '加密明文不能为空';
        }

        _encryption.Recipients.Add(cert);
        _encryption.Content = plaintext;

        //执行加密方法，并返回base64字符串
        var szEnvelopedData = _encryption.Encrypt(CAPICOM_ENCODE_BASE64);
        return szEnvelopedData;
    }

    /*
    * RSA非对称解密
    * @param cert 用于解密的证书
    * @param ciphertext 密文
    * @return 正确解密返回解密字符串，其他情况返回空
    */
    function _decrypt(cert, ciphertext) {
        if (ciphertext == "") {
            throw "传入的密文不能为空";
        }

        if (cert == null) {
            throw "传入的数字证书不能为空";
        }

        _encryption.Recipients.Add(cert);
        _encryption.Decrypt(ciphertext);

        var szEnvelopedData = _encryption.Content;
        return szEnvelopedData;
    }
    /*
    * 使用指定证书进行非对称加密数据
    * @param cert 数字证书对象
    * @param plaintext 待加密的明文字符串
    */
    this.RSAEncryptDataByCert = function (cert, plaintext) {
        return _encrypt(cert, plaintext);
    }

    /*
    * 使用指定证书非对称解密数据
    * @param cert 数字证书对象
    * @param ciphertext 密文
    * @return 返回解密后的字符串，如果传入的密文为空则会抛异常
    */
    this.RSADecryptDataByCert = function (cert, ciphertext) {
        return _decrypt(cert, ciphertext);
    }
}

/*
*  基于数字证书体系的API，实现了对数字证书的操作、非对称加解密、数字签名等功能
*  作者：mini188
*/
Mini.Digital.Api = function () {
    var _storename;
    var _issued;
    var _store = new Mini.Digital.Store(); //证书存储位置
    var _encrypt = new Mini.Digital.Encrypted(); //加解密
    var _error; //错误信息

    /*
    * 初始化配置
    */
    function _configure(configuration) {
        _issued = configuration.issued || '';
        _storename = configuration.storename || 'my';

        if (!_store) {
            _store = new Mini.Digital.Store();
        }
        _store.OpenStore(_storename, _issued);
    }

    

    /*
    * 初始化方法，用于初始化一些参数，可以通过参数传入
    */
    this.Configure = function (configuration) {
        _configure.call(this, configuration);
    }

    /*
    * 读取单个证书，如果读取到了多个类型的证书，则会弹出框供用户选择
    * @return 返回选择的证书对象
    */
    this.GetSingleCert = function () {
        return _store.GetCert();
    }

    /*
    * 读取当前store下的符合条件的证书列表并返回
    * @return 返回证书列表，如果未找到证书则返回null
    */
    this.GetCertList = function () {
        return _store.GetCertList();
    }

    this.FindCertByHash = function (hash) {
        return _store.FindCertByHash(hash);
    }

    /*
    * 非对称加密数据
    * @param plaintext 待加密的明文字符串
    * @return 返回加密后的字符串，其他情况返回null
    */
    this.RSAEncryptData = function (plaintext) {
        var cert = _store.GetCert();
        if (!cert) {
            return null;
        }

        return _encrypt.RSAEncryptDataByCert(cert, plaintext);
    }

    /*
    * 非对称解密数据
    * @param ciphertext 密文
    * @return 返回解密后的字符串，否则返回null
    */
    this.RSADecryptData = function (ciphertext) {
        var cert = _store.GetCert();
        if (!cert) {
            return null;
        }
        return _encrypt.RSADecryptDataByCert(cert, ciphertext);
    }

    /*
    * 获取hash值
    * @param sourcedata 待hash的数据
    * @return 返回hash结果，失败返回null
    */
    this.GetHash = function (sourcedata) {
        var hashedData = new ActiveXObject("CAPICOM.HashedData");
        hashedData.Algorithm = CAPICOM_HASH_ALGORITHM_SHA1;
        hashedData.Hash(sourcedata);
        return hashedData.Value;
    }
}
